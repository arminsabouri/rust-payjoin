mod error;

pub use error::{ResponderError, ResponderSessionError};
use serde::{Deserialize, Serialize};

use crate::hpke::{HpkeKeyPair, HpkePublicKey};
use crate::multiparty::bootstrap_transport::PostIo;
use crate::multiparty::participant::{
    AwaitingParticipantContext, ParticipantAwaitingSessionParameters,
};
use crate::multiparty::persist::EventfulTransition;
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::uri::MultipartyPjUri;
use crate::persist::NextStateTransition;
use crate::uri::PjParam;

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

/// Sans-io input to the responder stage.
///
/// The state machine never performs transport; an event only reports that some
/// I/O the driver performed on the machine's behalf has completed.
#[derive(Debug, Clone)]
pub enum ResponderEvent {
    /// The adapter durably posted message A (the responder reply key) to the
    /// initiator mailbox.
    ReplyKeyPosted,
}

impl Responder<Initialized> {
    /// The message-A post that hands the responder reply key to the initiator.
    ///
    /// The driver's mailbox adapter performs the OHTTP/HPKE and HTTP; the responder
    /// only supplies its exact target mailbox and keys. Message A carries an empty
    /// payload — its purpose is to convey the responder's reply key (the sender
    /// key) to the initiator.
    pub fn post_io(&self) -> Result<PostIo, ResponderError> {
        self.context.ensure_not_expired()?;
        let PjParam::V2(v2) = &self.context.pj_param else {
            return Err(ResponderError::NotV2);
        };
        Ok(PostIo {
            ohttp_keys: v2.ohttp_keys().clone(),
            directory: v2.directory().clone(),
            target: v2.endpoint(),
            recipient: v2.receiver_pubkey().clone(),
            sender: self.context.responder_key.clone(),
            payload: Vec::new(),
        })
    }

    /// Advance the responder in response to one [`ResponderEvent`].
    ///
    /// Sans-io: the event only reports that I/O the driver performed on the
    /// machine's behalf has completed. This never performs transport itself.
    pub fn step(
        &self,
        event: ResponderEvent,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, ResponderSessionError> {
        match event {
            ResponderEvent::ReplyKeyPosted => self.record_reply_key_posted(),
        }
    }

    fn record_reply_key_posted(
        &self,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, ResponderSessionError> {
        let sent_reply_key = self.context.responder_public_key().clone();
        let participant_context = match self.context.participant_context() {
            Ok(ctx) => ctx,
            Err(err) =>
                return EventfulTransition::fatal(
                    MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                    err,
                ),
        };
        EventfulTransition::success(
            [MultipartySessionEvent::ResponderSentReplyKey],
            MultipartySession::ParticipantAwaitingSessionParameters(
                ParticipantAwaitingSessionParameters {
                    parameters_mailbox_public_key: sent_reply_key,
                    context: participant_context,
                },
            ),
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
