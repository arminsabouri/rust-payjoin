mod error;

pub use error::{ResponderError, ResponderSessionError};
use serde::{Deserialize, Serialize};

use crate::hpke::{encrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::multiparty::participant::{
    AwaitingParticipantContext, ParticipantAwaitingSessionParameters,
};
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::uri::MultipartyPjUri;
use crate::ohttp::{ohttp_encapsulate, process_post_res};
use crate::persist::{MaybeFatalTransition, NextStateTransition};
use crate::uri::PjParam;
use crate::{IntoUrl, Request};

/// Persistent context for a multiparty responder session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponderContext {
    responder_key: HpkeKeyPair,
    pj_param: PjParam,
    /// Original BIP-321 URI the responder accepted.
    uri: String,
    /// Initiator HPKE public key from the multiparty Payjoin URI (`pj` receiver pubkey).
    pub(crate) initiator_public_key: HpkePublicKey,
}

impl ResponderContext {
    pub fn pj_param(&self) -> &PjParam { &self.pj_param }

    pub fn uri(&self) -> &str { &self.uri }

    fn ensure_not_expired(&self) -> Result<(), ResponderError> {
        let PjParam::V2(v2) = &self.pj_param else {
            return Err(ResponderError::NotV2);
        };
        if v2.expiration().elapsed() {
            return Err(ResponderError::Expired);
        }
        Ok(())
    }

    pub(crate) fn participant_context(&self) -> Result<AwaitingParticipantContext, ResponderError> {
        self.ensure_not_expired()?;
        let PjParam::V2(v2) = &self.pj_param else {
            return Err(ResponderError::NotV2);
        };
        Ok(AwaitingParticipantContext::new(
            self.responder_key.clone(),
            v2.directory().clone(),
            v2.ohttp_keys().clone(),
            self.initiator_public_key.clone(),
        ))
    }

    pub(crate) fn responder_public_key(&self) -> &HpkePublicKey { self.responder_key.public_key() }
}

/// Multiparty responder state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Responder<State> {
    pub(crate) state: State,
    pub(crate) context: ResponderContext,
}

pub struct ResponderBuilder;

impl ResponderBuilder {
    /// Start a responder session from a multiparty BIP-321 Payjoin URI.
    pub fn from_uri(
        uri: MultipartyPjUri,
    ) -> Result<NextStateTransition<MultipartySessionEvent, Responder<Initialized>>, ResponderError>
    {
        let pj_param = uri.pj_param().clone();
        let PjParam::V2(v2) = &pj_param else {
            return Err(ResponderError::NotV2);
        };
        if v2.expiration().elapsed() {
            return Err(ResponderError::Expired);
        }

        let initiator_public_key = v2.receiver_pubkey().clone();
        let context = ResponderContext {
            responder_key: HpkeKeyPair::gen_keypair(),
            pj_param,
            uri: uri.as_str().to_string(),
            initiator_public_key,
        };

        Ok(NextStateTransition::success(
            MultipartySessionEvent::ResponderCreated(context.clone()),
            Responder { state: Initialized {}, context },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {}

impl Responder<Initialized> {
    fn post_reply_body(
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        ResponderError,
    > {
        self.context.ensure_not_expired()?;
        let PjParam::V2(_) = &self.context.pj_param else {
            return Err(ResponderError::NotV2);
        };

        let (ohttp_keys, initiator_pubkey, mailbox_url) = match &self.context.pj_param {
            PjParam::V2(v2) => (v2.ohttp_keys(), v2.receiver_pubkey(), v2.endpoint()),
            #[cfg(feature = "v1")]
            PjParam::V1(_) => return Err(ResponderError::NotV2),
        };

        let message_a = encrypt_message_a(
            Vec::new(),
            self.context.responder_key.public_key(),
            initiator_pubkey,
        )
        .map_err(ResponderError::Hpke)?;

        ohttp_encapsulate(ohttp_keys, "POST", mailbox_url.as_str(), Some(&message_a))
            .map_err(ResponderError::OhttpEncapsulation)
    }

    /// Create an OHTTP encapsulated HTTP POST carrying message A (responder reply key).
    pub fn create_post_reply_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), ResponderError> {
        let (body, ohttp_ctx) = self.post_reply_body()?;
        let relay_url =
            crate::ohttp::full_relay_url(ohttp_relay, &self.context.pj_param.endpoint_url())?;
        let req = Request::new_v2(&relay_url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process the directory response after posting the responder reply key.
    pub fn process_post_reply_response(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransition<
        MultipartySessionEvent,
        ParticipantAwaitingSessionParameters,
        ResponderSessionError,
    > {
        let current_state = self.clone();
        if let Err(directory_error) = process_post_res(body, context) {
            let err = ResponderError::DirectoryResponse(directory_error);
            if let ResponderError::DirectoryResponse(ref e) = err {
                if !e.is_fatal() {
                    return MaybeFatalTransition::transient(err);
                }
            }
            return MaybeFatalTransition::fatal(
                MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                err,
            );
        }

        let sent_reply_key = current_state.context.responder_public_key().clone();
        let participant_context = match current_state.context.participant_context() {
            Ok(ctx) => ctx,
            Err(err) =>
                return MaybeFatalTransition::fatal(
                    MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                    err,
                ),
        };
        MaybeFatalTransition::success(
            MultipartySessionEvent::ResponderSentReplyKey,
            ParticipantAwaitingSessionParameters {
                parameters_mailbox_public_key: sent_reply_key,
                context: participant_context,
            },
        )
    }

    pub(crate) fn apply_sent_reply_key(self) -> MultipartySession {
        MultipartySession::ParticipantAwaitingSessionParameters(
            ParticipantAwaitingSessionParameters {
                parameters_mailbox_public_key: self.context.responder_public_key().clone(),
                context: self
                    .context
                    .participant_context()
                    .expect("replay only applies after responder posted reply key"),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentReplyKey {}

impl Responder<SentReplyKey> {}
