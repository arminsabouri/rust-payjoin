mod error;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
pub use error::{InitiatorError, InitiatorSessionError};
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::Duration;

use crate::hpke::{decrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::multiparty::participant::{AwaitingSessionParameters, Participant, ParticipantContext};
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::uri::{build_multiparty_pj_uri, MultipartyPjUri};
use crate::ohttp::{ohttp_encapsulate, process_get_res};
use crate::persist::{MaybeFatalTransitionWithNoResults, NextStateTransition};
use crate::receive::v2::mailbox_endpoint;
use crate::uri::{PjParam, ShortId};
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Persistent context for a multiparty initiator session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiatorContext {
    initiator_key: HpkeKeyPair,
    directory: Url,
    ohttp_keys: OhttpKeys,
    /// Responder reply key from message A, once the initiator has polled the directory.
    pub(crate) responder_public_key: Option<HpkePublicKey>,
}

impl InitiatorContext {
    fn initiator_mailbox_id(&self) -> ShortId {
        sha256::Hash::hash(&self.initiator_key.public_key().to_compressed_bytes()).into()
    }

    fn session_parameters_mailbox_id(&self) -> Option<ShortId> {
        if let Some(responder_public_key) = &self.responder_public_key {
            Some(sha256::Hash::hash(&responder_public_key.to_compressed_bytes()).into())
        } else {
            None
        }
    }

    pub(crate) fn participant_context(
        &self,
        responder_public_key: HpkePublicKey,
    ) -> ParticipantContext {
        ParticipantContext::new(
            self.initiator_key.clone(),
            self.directory.clone(),
            self.ohttp_keys.clone(),
            responder_public_key,
            self.session_parameters_mailbox_id().expect(
                "session parameters mailbox id must be present TODO: this should not panic",
            ),
        )
    }
}

/// Multiparty initiator state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initiator<State> {
    pub(crate) state: State,
    pub(crate) context: InitiatorContext,
}

pub struct InitiatorBuilder(InitiatorContext);

impl InitiatorBuilder {
    pub fn new(
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
    ) -> Result<Self, crate::into_url::Error> {
        let initiator_key = HpkeKeyPair::gen_keypair();
        Ok(Self(InitiatorContext {
            initiator_key,
            directory: directory.into_url()?,
            ohttp_keys,
            responder_public_key: None,
        }))
    }

    pub fn build(self) -> NextStateTransition<MultipartySessionEvent, Initiator<Initialized>> {
        NextStateTransition::success(
            MultipartySessionEvent::InitiatorCreated(self.0.clone()),
            Initiator { state: Initialized {}, context: self.0 },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {}

fn initiator_pj_param(context: &InitiatorContext) -> PjParam {
    // v2 `pj` endpoints require an EX fragment; session expiration is not modeled yet.
    let expiration = crate::time::Time::from_now(Duration::from_secs(60 * 60 * 24))
        .expect("placeholder expiration should be representable");
    PjParam::V2(crate::uri::v2::PjParam::new(
        context.directory.clone(),
        context.initiator_mailbox_id(),
        expiration,
        context.ohttp_keys.clone(),
        context.initiator_key.public_key().clone(),
    ))
}

/// Build a BIP-321 Payjoin URI for responders (`pj` + `mppj=1`, no address).
pub(crate) fn pj_uri(context: &InitiatorContext) -> MultipartyPjUri {
    build_multiparty_pj_uri(&initiator_pj_param(context))
}

impl Initiator<Initialized> {
    /// BIP-321 Payjoin URI shared with responders (`pj` + `mppj=1`, no address).
    pub fn pj_uri(&self) -> MultipartyPjUri { pj_uri(&self.context) }

    fn poll_req_body(
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        InitiatorError,
    > {
        let poll_target =
            mailbox_endpoint(&self.context.directory, &self.context.initiator_mailbox_id());
        ohttp_encapsulate(&self.context.ohttp_keys, "GET", poll_target.as_str(), None)
            .map_err(InitiatorError::OhttpEncapsulation)
    }

    /// Create an OHTTP encapsulated HTTP GET request to poll the initiator mailbox.
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), InitiatorError> {
        let (body, ohttp_ctx) = self.poll_req_body()?;
        let relay_url = crate::ohttp::full_relay_url(ohttp_relay, &self.context.directory)?;
        let req = Request::new_v2(&relay_url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process the response to a poll request from the Payjoin Directory.
    ///
    /// On success, transitions after decrypting and parsing only the sender's reply key from
    /// message A. Returns no-results when the directory has nothing yet (HTTP 202 ACCEPTED).
    pub fn process_poll_request(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        MultipartySessionEvent,
        Participant<AwaitingSessionParameters>,
        Initiator<Initialized>,
        InitiatorSessionError,
    > {
        // TODO: this should transition to a common state where responder and initator are waiting
        let current_state = self.clone();
        let responder_public_key = match self.inner_process_poll_res(body, context) {
            Ok(responder_public_key) => responder_public_key,
            Err(e) => match &e {
                InitiatorError::DirectoryResponse(directory_error)
                    if !directory_error.is_fatal() =>
                {
                    return MaybeFatalTransitionWithNoResults::transient(e);
                }
                _ =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                        e,
                    ),
            },
        };

        if let Some(responder_public_key) = responder_public_key {
            MaybeFatalTransitionWithNoResults::success(
                MultipartySessionEvent::InitiatorRetrievedReplyKey(responder_public_key.clone()),
                Participant {
                    state: AwaitingSessionParameters {},
                    context: current_state.context.participant_context(responder_public_key),
                },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(current_state)
        }
    }

    fn inner_process_poll_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<HpkePublicKey>, InitiatorError> {
        let body =
            match process_get_res(body, context).map_err(InitiatorError::DirectoryResponse)? {
                Some(body) => body,
                None => return Ok(None),
            };

        let (_, reply_key) = decrypt_message_a(&body, self.context.initiator_key.secret_key())
            .map_err(InitiatorError::Hpke)?;

        Ok(Some(reply_key))
    }

    pub(crate) fn apply_retrieved_reply_key(
        self,
        responder_public_key: HpkePublicKey,
    ) -> MultipartySession {
        MultipartySession::ParticipantAwaitingSessionParameters(Participant {
            state: AwaitingSessionParameters {},
            context: self.context.participant_context(responder_public_key),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasReplyKey {}
impl Initiator<HasReplyKey> {}
