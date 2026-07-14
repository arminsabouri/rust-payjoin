mod error;

use std::fmt;

use bitcoin::hashes::{sha256, Hash};
use error::InternalSessionCreatorSessionError;
pub use error::SessionCreatorSessionError;
use serde::{Deserialize, Serialize};

use crate::hpke::{HpkeKeyPair, HpkePublicKey};
use crate::multiparty::bootstrap_transport::PostIo;
use crate::multiparty::participant::{
    HasSessionParameters, Participant, ParticipantAwaitingSessionParameters, ParticipantContext,
};
use crate::multiparty::persist::{
    EventfulTransition, GraduationError, MultipartyGraduationTransition, MultipartySessionRegistry,
};
pub use crate::multiparty::session::replay_event_log;
use crate::multiparty::session::{
    collect_open_sessions_awaiting_parameters_with_persisters, CollectAwaitingParametersError,
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::session_parameters::SessionParameters;
use crate::ohttp::OhttpEncapsulationError;
use crate::persist::{NextStateTransition, SessionPersister};
use crate::receive::v2::mailbox_endpoint;
use crate::uri::ShortId;
use crate::{OhttpKeys, Url};

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

    fn into_participant_context(self) -> ParticipantContext {
        ParticipantContext {
            directory: self.directory,
            ohttp_keys: self.ohttp_keys,
            session_parameters: self.session_parameters,
        }
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

/// Errors from creating distribution requests before a directory response is processed.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionCreatorError {
    ParseUrl(crate::into_url::Error),
    OhttpEncapsulation(OhttpEncapsulationError),
    NoPendingParticipants,
    /// Collected participants use different Payjoin Directory URLs.
    InconsistentDirectory,
    /// Two or more participants share the same mailbox public key.
    DuplicateParticipant,
}

impl fmt::Display for SessionCreatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseUrl(err) => write!(f, "cannot parse url: {err}"),
            Self::OhttpEncapsulation(err) => write!(f, "ohttp encapsulation error: {err}"),
            Self::NoPendingParticipants =>
                write!(f, "no participants to distribute session parameters to"),
            Self::InconsistentDirectory =>
                write!(f, "participants do not share the same directory URL"),
            Self::DuplicateParticipant => write!(f, "duplicate participant mailbox public key"),
        }
    }
}

impl std::error::Error for SessionCreatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseUrl(err) => Some(err),
            Self::OhttpEncapsulation(err) => Some(err),
            Self::NoPendingParticipants
            | Self::InconsistentDirectory
            | Self::DuplicateParticipant => None,
        }
    }
}

impl From<crate::into_url::Error> for SessionCreatorError {
    fn from(value: crate::into_url::Error) -> Self { Self::ParseUrl(value) }
}

impl From<OhttpEncapsulationError> for SessionCreatorError {
    fn from(value: OhttpEncapsulationError) -> Self { Self::OhttpEncapsulation(value) }
}

/// Errors from [`SessionCreatorBuilder::build_and_promote`] and
/// [`MultipartyGraduationTransition::save`].
pub enum SessionCreatorPromoteError<R: MultipartySessionRegistry> {
    Collect(CollectAwaitingParametersError<R>),
    Build(SessionCreatorError),
    Graduation(GraduationError<R::Error, <R::Persister as SessionPersister>::InternalStorageError>),
}

impl<R: MultipartySessionRegistry> fmt::Debug for SessionCreatorPromoteError<R>
where
    R::Error: fmt::Debug,
    <R::Persister as SessionPersister>::InternalStorageError: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collect(err) => f.debug_tuple("Collect").field(err).finish(),
            Self::Build(err) => f.debug_tuple("Build").field(err).finish(),
            Self::Graduation(err) => f.debug_tuple("Graduation").field(err).finish(),
        }
    }
}

impl<R: MultipartySessionRegistry> fmt::Display for SessionCreatorPromoteError<R>
where
    R::Error: fmt::Display,
    <R::Persister as SessionPersister>::InternalStorageError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collect(err) => write!(f, "collect awaiting sessions: {err}"),
            Self::Build(err) => write!(f, "session creator build: {err}"),
            Self::Graduation(err) => write!(f, "session creator promotion: {err}"),
        }
    }
}

impl<R: MultipartySessionRegistry + 'static> std::error::Error for SessionCreatorPromoteError<R>
where
    R::Error: std::error::Error + 'static,
    <R::Persister as SessionPersister>::InternalStorageError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Collect(err) => Some(err),
            Self::Build(err) => Some(err),
            Self::Graduation(err) => Some(err),
        }
    }
}

pub struct SessionCreatorBuilder;

impl SessionCreatorBuilder {
    /// Build a session-creator promotion from open awaiting sessions in `registry`.
    pub fn build_and_promote<R>(
        registry: &R,
        session_parameters: SessionParameters,
    ) -> Result<
        MultipartyGraduationTransition<R::Persister, SessionCreator<CollectedSessions>>,
        SessionCreatorPromoteError<R>,
    >
    where
        R: MultipartySessionRegistry,
        R::Persister: Clone,
    {
        let awaiting = collect_open_sessions_awaiting_parameters_with_persisters(registry)
            .map_err(SessionCreatorPromoteError::Collect)?;
        let (creator, committed_awaiting) =
            build_from_open_awaiting(session_parameters.clone(), &awaiting)
                .map_err(SessionCreatorPromoteError::Build)?;

        Ok(MultipartyGraduationTransition::new(
            committed_awaiting,
            MultipartySessionEvent::Closed(MultipartySessionOutcome::Graduated(session_parameters)),
            creator,
        ))
    }
}

#[allow(clippy::type_complexity)]
fn build_from_open_awaiting<P>(
    session_parameters: SessionParameters,
    awaiting: &[(&P, ParticipantAwaitingSessionParameters)],
) -> Result<
    (NextStateTransition<MultipartySessionEvent, SessionCreator<CollectedSessions>>, Vec<P>),
    SessionCreatorError,
>
where
    P: Clone,
{
    let mut iter = awaiting.iter();
    let (first_persister, first) = iter.next().ok_or(SessionCreatorError::NoPendingParticipants)?;
    let directory = first.context.directory.clone();
    let mut participant_keys = vec![first.parameters_mailbox_public_key().clone()];
    let mut committed_awaiting = vec![(*first_persister).clone()];

    for (persister, participant) in iter {
        if participant.context.directory != directory {
            return Err(SessionCreatorError::InconsistentDirectory);
        }
        let key = participant.parameters_mailbox_public_key().clone();
        if participant_keys.contains(&key) {
            return Err(SessionCreatorError::DuplicateParticipant);
        }
        participant_keys.push(key);
        committed_awaiting.push((*persister).clone());
    }

    let participants = participant_keys
        .into_iter()
        .map(|public_key| PendingParticipant { public_key, parameters_delivered: false })
        .collect();

    let context = SessionCreatorContext {
        creator_key: HpkeKeyPair::gen_keypair(),
        directory,
        ohttp_keys: first.context.ohttp_keys.clone(),
        session_parameters,
        participants,
    };

    let creator = NextStateTransition::success(
        MultipartySessionEvent::SessionCreatorCreated(context.clone()),
        SessionCreator { state: CollectedSessions {}, context },
    );

    Ok((creator, committed_awaiting))
}

/// Session creator has collected participant mailboxes and is distributing parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedSessions {}

/// Sans-io input to the session-creator stage.
///
/// The state machine never performs transport; an event only reports that some
/// I/O the driver performed on the machine's behalf has completed.
#[derive(Debug, Clone)]
pub enum SessionCreatorEvent {
    /// The adapter durably posted session parameters to `recipient`'s mailbox.
    ParametersDeliveredTo(HpkePublicKey),
}

/// Typed transition after session parameters are acknowledged by one participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParametersDelivery {
    /// More participants still need parameters.
    Collecting(SessionCreator<CollectedSessions>),
    /// Every participant has acknowledged delivery.
    Distributed(Participant<HasSessionParameters>),
}

/// Persisted outcome of processing one session-parameters distribution response.
pub type ParametersDistributionTransition =
    EventfulTransition<MultipartySessionEvent, ParametersDelivery, SessionCreatorSessionError>;

impl From<ParametersDelivery> for MultipartySession {
    fn from(delivery: ParametersDelivery) -> Self {
        match delivery {
            ParametersDelivery::Collecting(state) =>
                MultipartySession::SessionCreatorCollectedSessions(state),
            ParametersDelivery::Distributed(state) =>
                MultipartySession::ParticipantHasSessionParameters(state),
        }
    }
}

impl SessionCreator<CollectedSessions> {
    /// Next participant that still needs session parameters, if any.
    pub fn next_undelivered_participant(&self) -> Option<&HpkePublicKey> {
        self.context.next_undelivered().map(|p| &p.public_key)
    }

    /// The message-A post that hands session parameters to the next participant
    /// still awaiting them, or `None` once every participant has been served.
    ///
    /// The driver's mailbox adapter performs the OHTTP/HPKE and HTTP; the creator
    /// only supplies its exact target mailbox, keys, and the encoded parameters.
    /// The recipient is [`PostIo::recipient`]; the driver feeds it back as
    /// [`SessionCreatorEvent::ParametersDeliveredTo`].
    pub fn post_io(&self) -> Option<PostIo> {
        let recipient = self.context.next_undelivered()?.public_key.clone();
        let target = mailbox_endpoint(
            &self.context.directory,
            &SessionCreatorContext::participant_mailbox_id(&recipient),
        );
        Some(PostIo {
            ohttp_keys: self.context.ohttp_keys.clone(),
            directory: self.context.directory.clone(),
            target,
            recipient,
            sender: self.context.creator_key.clone(),
            payload: self.context.session_parameters.to_bytes(),
        })
    }

    /// Advance the session creator in response to one [`SessionCreatorEvent`].
    ///
    /// Sans-io: the event only reports that I/O the driver performed on the
    /// machine's behalf has completed. This never performs transport itself.
    pub fn step(
        &self,
        event: SessionCreatorEvent,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, SessionCreatorSessionError>
    {
        match event {
            SessionCreatorEvent::ParametersDeliveredTo(recipient) =>
                self.record_parameters_delivered_to(recipient),
        }
    }

    fn record_parameters_delivered_to(
        &self,
        recipient: HpkePublicKey,
    ) -> EventfulTransition<MultipartySessionEvent, MultipartySession, SessionCreatorSessionError>
    {
        let delivery = match self.clone().parameters_delivered_to(recipient.clone()) {
            Ok(delivery) => delivery,
            Err(e) =>
                return EventfulTransition::fatal(
                    MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                    e.into(),
                ),
        };

        let mut events =
            vec![MultipartySessionEvent::SessionCreatorParametersDeliveredTo(recipient)];
        if matches!(delivery, ParametersDelivery::Distributed(_)) {
            events.push(MultipartySessionEvent::SessionCreatorAllParametersDelivered);
        }

        ParametersDistributionTransition::success(events, delivery)
            .map_outcome(MultipartySession::from)
    }

    fn parameters_delivered_to(
        self,
        recipient: HpkePublicKey,
    ) -> Result<ParametersDelivery, InternalSessionCreatorSessionError> {
        let mut context = self.context;
        context.mark_parameters_delivered(&recipient)?;
        Ok(if context.all_parameters_delivered() {
            ParametersDelivery::Distributed(Participant::from_adopted_context(
                context.into_participant_context(),
            ))
        } else {
            ParametersDelivery::Collecting(SessionCreator { state: CollectedSessions {}, context })
        })
    }

    pub(crate) fn apply_parameters_delivered(self, recipient: HpkePublicKey) -> MultipartySession {
        let mut context = self.context;
        context
            .mark_parameters_delivered(&recipient)
            .expect("replay only applies valid ParametersDeliveredTo events");
        MultipartySession::SessionCreatorCollectedSessions(SessionCreator {
            state: CollectedSessions {},
            context,
        })
    }

    pub(crate) fn apply_all_parameters_delivered(self) -> MultipartySession {
        assert!(
            self.context.all_parameters_delivered(),
            "AllParametersDelivered only replays after every committed participant acknowledged"
        );
        MultipartySession::ParticipantHasSessionParameters(Participant::from_adopted_context(
            self.context.into_participant_context(),
        ))
    }
}
