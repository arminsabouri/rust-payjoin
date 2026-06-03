mod error;

use std::fmt;

use bitcoin::hashes::{sha256, Hash};
use error::InternalSessionCreatorSessionError;
pub use error::SessionCreatorSessionError;
use serde::{Deserialize, Serialize};

use crate::hpke::{encrypt_message_a, HpkeKeyPair, HpkePublicKey};
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::session_parameters::SessionParameters;
use crate::ohttp::{ohttp_encapsulate, process_post_res, OhttpEncapsulationError};
use crate::persist::{MaybeFatalTransition, NextStateTransition};
use crate::receive::v2::mailbox_endpoint;
use crate::uri::ShortId;
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Delivery status for a participant awaiting session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingParticipant {
    /// Responder reply key; also the mailbox id for this participant.
    pub public_key: HpkePublicKey,
    /// Whether session parameters were sent and the response was processed
    pub parameters_delivered: bool,
}

/// Persistent context for a multiparty session creator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCreatorContext {
    creator_key: HpkeKeyPair,
    directory: Url,
    ohttp_keys: OhttpKeys,
    pub(crate) session_parameters: SessionParameters,
    participants: Vec<PendingParticipant>,
}

impl SessionCreatorContext {
    fn participant_mailbox_id(peer: &HpkePublicKey) -> ShortId {
        sha256::Hash::hash(&peer.to_compressed_bytes()).into()
    }

    fn next_undelivered(&self) -> Option<&PendingParticipant> {
        self.participants.iter().find(|p| !p.parameters_delivered)
    }

    pub(crate) fn all_parameters_delivered(&self) -> bool {
        !self.participants.is_empty() && self.participants.iter().all(|p| p.parameters_delivered)
    }

    pub(crate) fn mark_parameters_delivered(
        &mut self,
        recipient: &HpkePublicKey,
    ) -> Result<(), InternalSessionCreatorSessionError> {
        let participant = self
            .participants
            .iter_mut()
            .find(|p| &p.public_key == recipient)
            .ok_or(InternalSessionCreatorSessionError::UnknownParticipant)?;
        if participant.parameters_delivered {
            return Err(InternalSessionCreatorSessionError::AlreadyDelivered);
        }
        participant.parameters_delivered = true;
        Ok(())
    }
}

/// Multiparty session-creator state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCreator<State> {
    pub(crate) state: State,
    pub(crate) context: SessionCreatorContext,
}

/// Outbound session-parameters distribution for one participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionParametersDistributionMessage {
    /// Participant whose mailbox receives the encrypted session parameters.
    pub recipient: HpkePublicKey,
}

/// Errors from creating distribution requests before a directory response is processed.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionCreatorError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    NoPendingParticipants,
}

impl fmt::Display for SessionCreatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseUrl(err) => write!(f, "cannot parse url: {err}"),
            Self::OhttpEncapsulation(err) => write!(f, "ohttp encapsulation error: {err}"),
            Self::NoPendingParticipants =>
                write!(f, "no participants to distribute session parameters to"),
        }
    }
}

impl std::error::Error for SessionCreatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseUrl(err) => Some(err),
            Self::OhttpEncapsulation(err) => Some(err),
            Self::NoPendingParticipants => None,
        }
    }
}

impl From<crate::into_url::Error> for SessionCreatorError {
    fn from(value: crate::into_url::Error) -> Self { Self::ParseUrl(value) }
}

impl From<OhttpEncapsulationError> for SessionCreatorError {
    fn from(value: OhttpEncapsulationError) -> Self { Self::OhttpEncapsulation(value) }
}

pub struct SessionCreatorBuilder {
    session_parameters: SessionParameters,
    participant_keys: Vec<HpkePublicKey>,
    directory: Url,
    ohttp_keys: OhttpKeys,
}

impl SessionCreatorBuilder {
    /// Start a session-creator that will distribute [`SessionParameters`] to each participant.
    ///
    /// `participant_keys` are responder reply keys from message A; each key identifies the
    /// participant's mailbox on the Payjoin Directory.
    pub fn new(
        session_parameters: SessionParameters,
        participant_keys: impl IntoIterator<Item = HpkePublicKey>,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
    ) -> Result<Self, crate::into_url::Error> {
        let participant_keys: Vec<_> = participant_keys.into_iter().collect();
        Ok(Self {
            session_parameters,
            participant_keys,
            directory: directory.into_url()?,
            ohttp_keys,
        })
    }

    pub fn build(
        self,
    ) -> Result<
        NextStateTransition<MultipartySessionEvent, SessionCreator<CollectedSessions>>,
        SessionCreatorError,
    > {
        if self.participant_keys.is_empty() {
            return Err(SessionCreatorError::NoPendingParticipants);
        }

        let participants = self
            .participant_keys
            .into_iter()
            .map(|public_key| PendingParticipant { public_key, parameters_delivered: false })
            .collect();

        let context = SessionCreatorContext {
            creator_key: HpkeKeyPair::gen_keypair(),
            directory: self.directory,
            ohttp_keys: self.ohttp_keys,
            session_parameters: self.session_parameters,
            participants,
        };

        Ok(NextStateTransition::success(
            MultipartySessionEvent::SessionCreatorCreated(context.clone()),
            SessionCreator { state: CollectedSessions {}, context },
        ))
    }
}

/// Session creator has collected participant mailboxes and is distributing parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedSessions {}

/// Session parameters were delivered to every participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParametersDistributed {}

/// Typed transition after session parameters are acknowledged by one participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParametersDelivery {
    /// More participants still need parameters.
    Collecting(SessionCreator<CollectedSessions>),
    /// Every participant has acknowledged delivery.
    Distributed(SessionCreator<ParametersDistributed>),
}

impl From<ParametersDelivery> for MultipartySession {
    fn from(delivery: ParametersDelivery) -> Self {
        match delivery {
            ParametersDelivery::Collecting(state) =>
                MultipartySession::SessionCreatorCollectedSessions(state),
            ParametersDelivery::Distributed(state) =>
                MultipartySession::SessionCreatorParametersDistributed(state),
        }
    }
}

impl SessionCreator<CollectedSessions> {
    /// Next participant that still needs session parameters, if any.
    pub fn next_undelivered_participant(&self) -> Option<&HpkePublicKey> {
        self.context.next_undelivered().map(|p| &p.public_key)
    }

    /// Build the next OHTTP POST carrying HPKE-encrypted session parameters for one participant.
    ///
    /// Returns `None` when every participant has already acknowledged delivery.
    pub fn next_session_parameters_distribution_message(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<
        Option<(SessionParametersDistributionMessage, Request, ohttp::ClientResponse)>,
        SessionCreatorError,
    > {
        let recipient = match self.context.next_undelivered() {
            Some(p) => p.public_key.clone(),
            None => return Ok(None),
        };

        let (body, ohttp_ctx) =
            self.distribution_post_body(&recipient).map_err(SessionCreatorError::from_session)?;
        let relay_url = crate::ohttp::full_relay_url(ohttp_relay, &self.context.directory)?;
        let req = Request::new_v2(&relay_url, &body);
        Ok(Some((SessionParametersDistributionMessage { recipient }, req, ohttp_ctx)))
    }

    /// Process the directory response after posting session parameters to a participant mailbox.
    pub fn process_session_parameters_distribution_response(
        self,
        recipient: HpkePublicKey,
        body: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> MaybeFatalTransition<MultipartySessionEvent, ParametersDelivery, SessionCreatorSessionError>
    {
        match process_post_res(body, ohttp_context) {
            Ok(()) => {}
            Err(e) => {
                if !e.is_fatal() {
                    return MaybeFatalTransition::transient(
                        InternalSessionCreatorSessionError::DirectoryResponse(e).into(),
                    );
                }
                // TODO: should we should treat all of these as transient and re-try?
                return MaybeFatalTransition::fatal(
                    MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                    InternalSessionCreatorSessionError::DirectoryResponse(e).into(),
                );
            }
        }

        let event = MultipartySessionEvent::SessionCreatorParametersDeliveredTo(recipient.clone());
        let delivery = match self.parameters_delivered_to(recipient) {
            Ok(delivery) => delivery,
            Err(e) => {
                return MaybeFatalTransition::fatal(
                    MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                    e.into(),
                );
            }
        };

        MaybeFatalTransition::success(event, delivery)
    }

    fn parameters_delivered_to(
        self,
        recipient: HpkePublicKey,
    ) -> Result<ParametersDelivery, InternalSessionCreatorSessionError> {
        let mut context = self.context;
        context.mark_parameters_delivered(&recipient)?;
        Ok(if context.all_parameters_delivered() {
            ParametersDelivery::Distributed(SessionCreator {
                state: ParametersDistributed {},
                context,
            })
        } else {
            ParametersDelivery::Collecting(SessionCreator { state: CollectedSessions {}, context })
        })
    }

    fn distribution_post_body(
        &self,
        recipient: &HpkePublicKey,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        InternalSessionCreatorSessionError,
    > {
        let params = self.context.session_parameters.to_bytes();
        let payload = encrypt_message_a(params, self.context.creator_key.public_key(), recipient)
            .map_err(InternalSessionCreatorSessionError::Hpke)?;

        let mailbox = mailbox_endpoint(
            &self.context.directory,
            &SessionCreatorContext::participant_mailbox_id(recipient),
        );

        ohttp_encapsulate(&self.context.ohttp_keys, "POST", mailbox.as_str(), Some(&payload))
            .map_err(InternalSessionCreatorSessionError::OhttpEncapsulation)
    }

    pub(crate) fn apply_parameters_delivered(self, recipient: HpkePublicKey) -> MultipartySession {
        self.parameters_delivered_to(recipient)
            .expect("replay only applies valid ParametersDeliveredTo events")
            .into()
    }
}

// TODO: session creator should just transition to being a participant not have a separate state
impl SessionCreator<ParametersDistributed> {}
impl SessionCreatorError {
    fn from_session(err: InternalSessionCreatorSessionError) -> Self {
        match err {
            InternalSessionCreatorSessionError::ParseUrl(e) => Self::ParseUrl(e),
            InternalSessionCreatorSessionError::OhttpEncapsulation(e) =>
                Self::OhttpEncapsulation(e),
            _ => unreachable!("distribution_post_body only returns URL, OHTTP, or HPKE errors"),
        }
    }
}
