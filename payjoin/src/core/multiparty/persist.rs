//! Multiparty session registry: one [`MultipartySessionRegistry`] per wallet.
//!
//! Each role keeps its own event log(s) on a [`crate::persist::SessionPersister`]. Wallets
//! register the logs they own and pass the returned persister handles into `.save(&persister)`
//! transitions. Closing awaiting logs and opening post-adoption logs is persisted through the
//! registry via [`SessionCreatorPromotionTransition::save`],
//! [`MultipartySessionRegistry::save_session_creator_promotion`], and
//! [`MultipartySessionRegistry::adopt_participant_parameters`].
//!
//! An initiator wallet that becomes session creator registers initiator bootstrap logs and the
//! session-creator log, then uses
//! [`crate::multiparty::collect_open_sessions_awaiting_parameters`] to find its own sessions
//! awaiting session parameters. Responder and other participant wallets use a separate registry
//! for bootstrap and post-adoption logs.

use core::fmt;
use std::error;

use crate::error::ReplayError;
use crate::multiparty::participant::{AwaitingSessionParameters, Participant, ParticipantContext};
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::session_creator::{
    CollectedSessions, SessionCreator, SessionCreatorPromoteError,
};
use crate::multiparty::SessionParameters;
use crate::persist::{
    InMemoryPersister, MaybeFatalTransitionWithNoResults, NextStateTransition, SessionPersister,
};

/// Index of many multiparty session persisters.
pub trait MultipartySessionRegistry {
    /// Registry-level errors (not per-log storage errors).
    type Error: error::Error + Send + Sync + 'static;
    /// Concrete persister type used by the registry.
    type Persister: SessionPersister<SessionEvent = MultipartySessionEvent>;

    /// Handles for session logs that are not closed.
    fn list_open(&self) -> Result<Vec<&Self::Persister>, Self::Error>;

    /// Create a new empty session log and return its persister handle.
    /// TODO: do we want to link the previous session with the new one?
    /// TODO: does not need to be mut. Use interior mutability for the inmemory registry.
    fn new_session(&mut self) -> Result<Self::Persister, Self::Error>;

    /// Close matching awaiting logs, register a session-creator log, and persist `transition`.
    ///
    /// Persists [`MultipartySessionEvent::SessionCreatorCreated`] first, then closes every log
    /// committed in `transition` at build time.
    fn save_session_creator_promotion(
        &mut self,
        transition: SessionCreatorPromotionTransition<Self::Persister>,
    ) -> Result<
        (Self::Persister, SessionCreator<CollectedSessions>),
        GraduationError<Self::Error, <Self::Persister as SessionPersister>::InternalStorageError>,
    >
    where
        Self::Persister: Clone,
    {
        let SessionCreatorPromotionTransition { promotion, committed_awaiting, creator } =
            transition;

        let creator_persister = self.new_session().map_err(GraduationError::Registry)?;
        let creator = creator.save(&creator_persister).map_err(GraduationError::Storage)?;

        for persister in &committed_awaiting {
            persister.save_event(promotion.close_event()).map_err(GraduationError::Storage)?;
            persister.close().map_err(GraduationError::Storage)?;
        }

        Ok((creator_persister, creator))
    }

    /// Close a participant awaiting-parameters log and register a successor log whose first
    /// event is [`MultipartySessionEvent::SessionParametersAdopted`].
    fn adopt_participant_parameters(
        &mut self,
        from: &Self::Persister,
        adoption: ParticipantParametersAdoption,
    ) -> Result<
        Self::Persister,
        GraduationError<Self::Error, <Self::Persister as SessionPersister>::InternalStorageError>,
    > {
        from.save_event(adoption.close_event()).map_err(GraduationError::Storage)?;
        from.close().map_err(GraduationError::Storage)?;
        let new = self.new_session().map_err(GraduationError::Registry)?;
        new.save_event(adoption.adopted_event()).map_err(GraduationError::Storage)?;
        Ok(new)
    }
}

/// Close an awaiting session log when session creator promotion replaces parameter polling on
/// that log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreatorPromotion {
    session_parameters: SessionParameters,
}

impl SessionCreatorPromotion {
    pub(crate) fn new(session_parameters: SessionParameters) -> Self { Self { session_parameters } }

    /// Session parameters the session creator will distribute.
    pub fn session_parameters(&self) -> &SessionParameters { &self.session_parameters }

    pub(crate) fn close_event(&self) -> MultipartySessionEvent {
        MultipartySessionEvent::Closed(MultipartySessionOutcome::Graduated(
            self.session_parameters.clone(),
        ))
    }
}

/// Promote open awaiting sessions to session-creator distribution.
///
/// Returned from [`crate::multiparty::session_creator::SessionCreatorBuilder::build_and_promote`].
/// The participant set is committed at build time together with the awaiting logs that will close
/// when [`SessionCreatorPromotionTransition::save`] persists
/// [`MultipartySessionEvent::SessionCreatorCreated`].
pub struct SessionCreatorPromotionTransition<P> {
    promotion: SessionCreatorPromotion,
    committed_awaiting: Vec<P>,
    creator: NextStateTransition<MultipartySessionEvent, SessionCreator<CollectedSessions>>,
}

impl<P> SessionCreatorPromotionTransition<P> {
    pub(crate) fn new(
        promotion: SessionCreatorPromotion,
        committed_awaiting: Vec<P>,
        creator: NextStateTransition<MultipartySessionEvent, SessionCreator<CollectedSessions>>,
    ) -> Self {
        Self { promotion, committed_awaiting, creator }
    }

    /// Persist [`MultipartySessionEvent::SessionCreatorCreated`], then close every awaiting log
    /// committed at build time.
    pub fn save<R>(
        self,
        registry: &mut R,
    ) -> Result<(R::Persister, SessionCreator<CollectedSessions>), SessionCreatorPromoteError<R>>
    where
        R: MultipartySessionRegistry<Persister = P>,
        P: Clone + SessionPersister<SessionEvent = MultipartySessionEvent>,
    {
        registry
            .save_session_creator_promotion(self)
            .map_err(SessionCreatorPromoteError::Graduation)
    }
}

/// Participant received session parameters; close the awaiting log and continue in a new log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantParametersAdoption {
    participant_context: ParticipantContext,
    session_parameters: SessionParameters,
}

impl ParticipantParametersAdoption {
    pub(crate) fn from_awaiting_participant(
        participant: &Participant<AwaitingSessionParameters>,
        session_parameters: SessionParameters,
    ) -> Self {
        Self { participant_context: participant.context.clone(), session_parameters }
    }

    /// Session parameters adopted into the post-adoption log.
    pub fn session_parameters(&self) -> &SessionParameters { &self.session_parameters }

    pub(crate) fn close_event(&self) -> MultipartySessionEvent {
        MultipartySessionEvent::Closed(MultipartySessionOutcome::Graduated(
            self.session_parameters.clone(),
        ))
    }

    pub(crate) fn adopted_event(&self) -> MultipartySessionEvent {
        let mut context = self.participant_context.clone();
        context.session_parameters = Some(self.session_parameters.clone());
        MultipartySessionEvent::SessionParametersAdopted(context)
    }
}

/// Outcome of polling for session parameters before persistence.
#[derive(Debug)]
pub enum SessionParametersPollTransition {
    /// Directory has nothing yet; resume from the returned participant.
    Stasis(Participant<AwaitingSessionParameters>),
    /// Parameters retrieved; persist via [`SessionParametersPollTransition::save`].
    Adoption(ParticipantParametersAdoption),
}

/// Outcome of persisting a session-parameters poll transition via the registry.
pub enum SessionParametersPollSaveOutcome<P> {
    /// Directory had nothing yet; resume polling from the returned participant.
    Stasis(Participant<AwaitingSessionParameters>),
    /// Parameters adopted into a new registry log; `from` is closed with
    /// [`MultipartySessionOutcome::Graduated`].
    Graduated(P),
}

impl<P> fmt::Debug for SessionParametersPollSaveOutcome<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stasis(participant) => f.debug_tuple("Stasis").field(participant).finish(),
            Self::Graduated(_) => f.write_str("Graduated"),
        }
    }
}

impl SessionParametersPollTransition {
    /// Persist this poll outcome via `registry`.
    ///
    /// Stasis requires no registry mutation. Adoption closes `from` and registers a new log
    /// whose first event is [`MultipartySessionEvent::SessionParametersAdopted`].
    pub fn save<R>(
        self,
        registry: &mut R,
        from: &R::Persister,
    ) -> Result<
        SessionParametersPollSaveOutcome<R::Persister>,
        GraduationError<R::Error, <R::Persister as SessionPersister>::InternalStorageError>,
    >
    where
        R: MultipartySessionRegistry,
    {
        match self {
            Self::Stasis(participant) => Ok(SessionParametersPollSaveOutcome::Stasis(participant)),
            Self::Adoption(adoption) => {
                let new = registry.adopt_participant_parameters(from, adoption)?;
                Ok(SessionParametersPollSaveOutcome::Graduated(new))
            }
        }
    }
}

/// Fatal or transient failure while polling for session parameters.
pub enum SessionParametersPollFailure {
    Transient(crate::multiparty::participant::ParticipantSessionError),
    Fatal(
        MaybeFatalTransitionWithNoResults<
            MultipartySessionEvent,
            (),
            Participant<AwaitingSessionParameters>,
            crate::multiparty::participant::ParticipantSessionError,
        >,
    ),
}

impl fmt::Debug for SessionParametersPollFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(err) => f.debug_tuple("Transient").field(err).finish(),
            Self::Fatal(_) => f.write_str("Fatal"),
        }
    }
}

/// Errors from [`MultipartySessionRegistry::adopt_participant_parameters`] and
/// [`MultipartySessionRegistry::save_session_creator_promotion`].
#[derive(Debug)]
pub enum GraduationError<E, S> {
    CollectRegistry(E),
    CollectReplay(ReplayError<MultipartySession, MultipartySessionEvent>),
    IncompleteAwaitingRegistry,
    Registry(E),
    Storage(S),
}

impl<E: fmt::Display, S: fmt::Display> fmt::Display for GraduationError<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CollectRegistry(err) =>
                write!(f, "collect awaiting sessions: registry error: {err}"),
            Self::CollectReplay(err) => write!(f, "collect awaiting sessions: replay error: {err}"),
            Self::IncompleteAwaitingRegistry => write!(
                f,
                "registry is missing an open awaiting log for a session creator participant"
            ),
            Self::Registry(err) => write!(f, "registry error: {err}"),
            Self::Storage(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl<E, S> error::Error for GraduationError<E, S>
where
    E: error::Error + 'static,
    S: error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::CollectRegistry(err) | Self::Registry(err) => Some(err),
            Self::CollectReplay(err) => Some(err),
            Self::IncompleteAwaitingRegistry => None,
            Self::Storage(err) => Some(err),
        }
    }
}

/// Errors from [`InMemoryMultipartyRegistry`].
///
/// The in-memory implementation does not currently fail registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {}

impl fmt::Display for RegistryError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result { match *self {} }
}

impl error::Error for RegistryError {}

/// In-memory registry for tests and prototyping.
///
/// Call [`MultipartySessionRegistry::new_session`] to register a new empty log and use the
/// returned [`InMemoryPersister`] directly in `.save(&persister)` flows.
// TODO: move this to test-utils
#[derive(Default)]
pub struct InMemoryMultipartyRegistry {
    sessions: Vec<InMemoryPersister<MultipartySessionEvent>>,
}

impl InMemoryMultipartyRegistry {
    pub fn new() -> Self { Self::default() }

    /// Register a new open session and return its handle.
    fn create_session(&mut self) -> InMemoryPersister<MultipartySessionEvent> {
        let persister = InMemoryPersister::default();
        self.sessions.push(persister.clone());
        persister
    }
}

impl MultipartySessionRegistry for InMemoryMultipartyRegistry {
    type Error = RegistryError;
    type Persister = InMemoryPersister<MultipartySessionEvent>;

    fn list_open(&self) -> Result<Vec<&Self::Persister>, Self::Error> {
        Ok(self
            .sessions
            .iter()
            .filter(|persister| !persister.inner.read().unwrap().is_closed)
            .collect())
    }

    fn new_session(&mut self) -> Result<Self::Persister, Self::Error> { Ok(self.create_session()) }
}
