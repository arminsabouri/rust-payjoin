mod error;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
pub use error::{InitiatorError, InitiatorSessionError};
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::Duration;

use crate::hpke::{HpkeKeyPair, HpkePublicKey};
use crate::multiparty::bootstrap_transport::PollIo;
use crate::multiparty::participant::{
    AwaitingParticipantContext, ParticipantAwaitingSessionParameters,
};
use crate::multiparty::persist::EventfulTransition;
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{MultipartySession, MultipartySessionEvent};
use crate::multiparty::uri::{build_multiparty_pj_uri, MultipartyPjUri};
use crate::persist::NextStateTransition;
use crate::receive::v2::mailbox_endpoint;
use crate::uri::{PjParam, ShortId};
use crate::{IntoUrl, OhttpKeys, Url};

/// Persistent context for a multiparty initiator session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitiatorContext {
    initiator_key: HpkeKeyPair,
    directory: Url,
    ohttp_keys: OhttpKeys,
}

impl InitiatorContext {
    fn initiator_mailbox_id(&self) -> ShortId {
        sha256::Hash::hash(&self.initiator_key.public_key().to_compressed_bytes()).into()
    }

    fn participant_context(
        &self,
        responder_public_key: HpkePublicKey,
    ) -> AwaitingParticipantContext {
        AwaitingParticipantContext::new(
            self.initiator_key.clone(),
            self.directory.clone(),
            self.ohttp_keys.clone(),
            responder_public_key,
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
        Ok(Self(InitiatorContext { initiator_key, directory: directory.into_url()?, ohttp_keys }))
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

/// Sans-io input to the initiator stage.
///
/// The state machine never performs transport; an event only reports that some
/// I/O the driver performed on the machine's behalf has completed. The "nothing
/// yet" poll outcome carries no event — the driver simply keeps polling.
#[derive(Debug, Clone)]
pub enum InitiatorEvent {
    /// The adapter polled the initiator mailbox and decrypted the responder's
    /// reply key.
    ReplyKeyRead(HpkePublicKey),
}

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

    /// The poll of the initiator mailbox that reads the responder's reply key.
    ///
    /// The driver's mailbox adapter performs the OHTTP/HPKE and HTTP; the initiator
    /// only supplies its exact mailbox target and the keypair that opens the
    /// inbound message A. The opened message's *sender* is the responder reply key
    /// (see [`SessionStage`](crate::multiparty::SessionStage) — the driver feeds it
    /// back as [`InitiatorEvent::ReplyKeyRead`]).
    pub fn poll_io(&self) -> PollIo {
        PollIo {
            ohttp_keys: self.context.ohttp_keys.clone(),
            directory: self.context.directory.clone(),
            target: mailbox_endpoint(&self.context.directory, &self.context.initiator_mailbox_id()),
            decrypt_key: self.context.initiator_key.clone(),
        }
    }

    /// Advance the initiator in response to one [`InitiatorEvent`].
    ///
    /// Sans-io: the event only reports that I/O the driver performed on the
    /// machine's behalf has completed. This never performs transport itself.
    // TODO: this should transition to a common state where responder and initiator are waiting.
    pub fn step(
        &self,
        event: InitiatorEvent,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, InitiatorSessionError> {
        match event {
            InitiatorEvent::ReplyKeyRead(responder_public_key) =>
                self.record_reply_key_read(responder_public_key),
        }
    }

    fn record_reply_key_read(
        &self,
        responder_public_key: HpkePublicKey,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, InitiatorSessionError> {
        EventfulTransition::success(
            [MultipartySessionEvent::InitiatorRetrievedReplyKey(responder_public_key.clone())],
            MultipartySession::ParticipantAwaitingSessionParameters(
                ParticipantAwaitingSessionParameters {
                    parameters_mailbox_public_key: responder_public_key.clone(),
                    context: self.context.participant_context(responder_public_key),
                },
            ),
        )
    }

    pub(crate) fn apply_retrieved_reply_key(
        self,
        responder_public_key: HpkePublicKey,
    ) -> MultipartySession {
        MultipartySession::ParticipantAwaitingSessionParameters(
            ParticipantAwaitingSessionParameters {
                parameters_mailbox_public_key: responder_public_key.clone(),
                context: self.context.participant_context(responder_public_key),
            },
        )
    }
}
