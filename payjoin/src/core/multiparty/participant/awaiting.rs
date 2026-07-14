use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use super::ParticipantError;
use crate::hpke::{HpkeKeyPair, HpkePublicKey};
use crate::multiparty::bootstrap_transport::PollIo;
use crate::multiparty::persist::{ParticipantParametersAdoption, SessionParametersPollTransition};
use crate::multiparty::session_parameters::SessionParameters;
use crate::receive::v2::mailbox_endpoint;
use crate::uri::ShortId;
use crate::{OhttpKeys, Url};

/// Persistent context for a multiparty participant awaiting session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitingParticipantContext {
    mailbox_key: HpkeKeyPair,
    pub(crate) directory: Url,
    pub ohttp_keys: OhttpKeys,
    /// The other party's HPKE public key (initiator for responders, responder for initiators).
    pub(crate) reply_key: HpkePublicKey,
}

impl AwaitingParticipantContext {
    pub(crate) fn new(
        mailbox_key: HpkeKeyPair,
        directory: Url,
        ohttp_keys: OhttpKeys,
        reply_key: HpkePublicKey,
    ) -> Self {
        Self { mailbox_key, directory: directory.payjoin_directory_origin(), ohttp_keys, reply_key }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantAwaitingSessionParameters {
    /// HPKE public key for the Payjoin Directory mailbox that receives session parameters.
    pub(crate) parameters_mailbox_public_key: HpkePublicKey,
    pub(crate) context: AwaitingParticipantContext,
}

/// Sans-io input to the awaiting-participant stage.
///
/// The state machine never performs transport; an event only reports that some
/// I/O the driver performed on the machine's behalf has completed. The "nothing
/// yet" poll outcome carries no event — the driver simply keeps polling.
#[derive(Debug, Clone)]
pub enum ParticipantAwaitingEvent {
    /// The adapter polled this participant's mailbox and decrypted the session
    /// parameters the creator distributed.
    ParametersRead(SessionParameters),
}

impl ParticipantAwaitingSessionParameters {
    /// Mailbox where the session creator POSTs parameters and this participant polls.
    pub(crate) fn parameters_mailbox_public_key(&self) -> &HpkePublicKey {
        &self.parameters_mailbox_public_key
    }

    fn parameters_mailbox_short_id(&self) -> ShortId {
        sha256::Hash::hash(&self.parameters_mailbox_public_key.to_compressed_bytes()).into()
    }

    /// The poll of this participant's mailbox that reads the creator's session
    /// parameters.
    ///
    /// The driver's mailbox adapter performs the OHTTP/HPKE and HTTP; the
    /// participant only supplies its exact mailbox target and the keypair that
    /// opens the inbound message A. The opened message's *payload* decodes to the
    /// [`SessionParameters`] (see [`parse_parameters`](Self::parse_parameters)).
    pub fn poll_io(&self) -> PollIo {
        PollIo {
            ohttp_keys: self.context.ohttp_keys.clone(),
            directory: self.context.directory.clone(),
            target: mailbox_endpoint(&self.context.directory, &self.parameters_mailbox_short_id()),
            decrypt_key: self.context.mailbox_key.clone(),
        }
    }

    /// Decode the session parameters from a polled message-A payload.
    pub fn parse_parameters(&self, payload: &[u8]) -> Result<SessionParameters, ParticipantError> {
        SessionParameters::from_message_a_body(payload).map_err(ParticipantError::SessionParameters)
    }

    /// Advance the awaiting participant in response to one
    /// [`ParticipantAwaitingEvent`].
    ///
    /// Sans-io: the event only reports that I/O the driver performed on the
    /// machine's behalf has completed. Adopting parameters is a *graduation* — it
    /// closes this log and opens a successor — so the returned transition is
    /// saved against the registry, not a single persister (see
    /// [`SessionParametersPollTransition::save`]). The "nothing yet" poll outcome
    /// carries no event; the driver simply keeps polling.
    pub fn step(&self, event: ParticipantAwaitingEvent) -> SessionParametersPollTransition {
        match event {
            ParticipantAwaitingEvent::ParametersRead(session_parameters) =>
                SessionParametersPollTransition::Adoption(
                    ParticipantParametersAdoption::from_awaiting_participant(
                        self,
                        session_parameters,
                    ),
                ),
        }
    }
}
