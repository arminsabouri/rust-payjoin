//! Multiparty session registry: one [`MultipartySessionRegistry`] per wallet.
//!
//! Each role keeps its own event log(s) on a [`crate::persist::SessionPersister`]. Wallets
//! register the logs they own and pass the returned persister handles into `.save(&persister)`
//! transitions. Closing awaiting logs and opening successor logs is persisted through
//! [`MultipartyGraduationTransition::save`] and [`MultipartySessionRegistry::new_session`].
//!
//! An initiator wallet that becomes session creator registers initiator bootstrap logs and the
//! session-creator log, then uses
//! [`crate::multiparty::collect_open_sessions_awaiting_parameters`] to find its own sessions
//! awaiting session parameters. Responder and other participant wallets use a separate registry
//! for bootstrap and post-adoption logs.

use core::fmt;
use std::error;

use crate::error::ReplayError;
use crate::multiparty::participant::{
    AwaitingParticipantContext, HasSessionParameters, Participant,
    ParticipantAwaitingSessionParameters, ParticipantContext,
};
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::SessionParameters;
use crate::persist::{
    ApiError, InMemoryPersister, InternalPersistedError, MaybeFatalTransitionWithNoResults,
    NextStateTransition, OptionalTransitionOutcome, PersistedError, SessionPersister,
};

enum EventfulPersistActions<Event> {
    NoOp,
    Save(Vec<Event>),
    SaveAndClose(Event),
}

impl<Event> EventfulPersistActions<Event> {
    fn execute<P>(self, persister: &P) -> Result<(), P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        match self {
            Self::NoOp => {}
            Self::Save(events) =>
                for event in events {
                    persister.save_event(event)?;
                },
            Self::SaveAndClose(event) => {
                persister.save_event(event)?;
                persister.close()?;
            }
        }
        Ok(())
    }
}

struct EventfulSuccess<Event, Outcome> {
    events: Vec<Event>,
    outcome: Outcome,
}

enum EventfulError<Event, Err> {
    Transient(Err),
    Fatal(Event, Err),
}

/// Saves one or more events, then returns a domain-specific transition outcome.
pub struct EventfulTransition<Event, Outcome, Err>(
    Result<EventfulSuccess<Event, Outcome>, EventfulError<Event, Err>>,
);

impl<Event, Outcome, Err> EventfulTransition<Event, Outcome, Err>
where
    Err: error::Error,
{
    pub(crate) fn success(events: impl IntoIterator<Item = Event>, outcome: Outcome) -> Self {
        Self(Ok(EventfulSuccess { events: events.into_iter().collect(), outcome }))
    }

    pub(crate) fn transient(error: Err) -> Self { Self(Err(EventfulError::Transient(error))) }

    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        Self(Err(EventfulError::Fatal(event, error)))
    }

    fn deconstruct(self) -> (EventfulPersistActions<Event>, Result<Outcome, ApiError<Err>>) {
        match self.0 {
            Ok(EventfulSuccess { events, outcome }) =>
                (EventfulPersistActions::Save(events), Ok(outcome)),
            Err(EventfulError::Transient(error)) =>
                (EventfulPersistActions::NoOp, Err(ApiError::Transient(error))),
            Err(EventfulError::Fatal(event, error)) =>
                (EventfulPersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<Outcome, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

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
}

/// Open a successor log, then close one or more existing logs.
pub struct MultipartyGraduationTransition<P, S> {
    from: Vec<P>,
    close_event: MultipartySessionEvent,
    successor: NextStateTransition<MultipartySessionEvent, S>,
}

impl<P, S> MultipartyGraduationTransition<P, S> {
    pub(crate) fn new(
        from: Vec<P>,
        close_event: MultipartySessionEvent,
        successor: NextStateTransition<MultipartySessionEvent, S>,
    ) -> Self {
        Self { from, close_event, successor }
    }

    pub fn save<R>(
        self,
        registry: &mut R,
    ) -> Result<
        (R::Persister, S),
        GraduationError<R::Error, <R::Persister as SessionPersister>::InternalStorageError>,
    >
    where
        R: MultipartySessionRegistry<Persister = P>,
        P: Clone + SessionPersister<SessionEvent = MultipartySessionEvent>,
    {
        let Self { from, close_event, successor } = self;

        let new = registry.new_session().map_err(GraduationError::Registry)?;
        let state = successor.save(&new).map_err(GraduationError::Storage)?;
        for persister in &from {
            persister.save_event(close_event.clone()).map_err(GraduationError::Storage)?;
            persister.close().map_err(GraduationError::Storage)?;
        }
        Ok((new, state))
    }
}

/// Participant received session parameters; close the awaiting log and continue in a new log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantParametersAdoption {
    participant_context: AwaitingParticipantContext,
    session_parameters: SessionParameters,
}

impl ParticipantParametersAdoption {
    pub(crate) fn from_awaiting_participant(
        participant: &ParticipantAwaitingSessionParameters,
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

    pub(crate) fn graduation_transition<P>(
        self,
        from: P,
    ) -> MultipartyGraduationTransition<P, Participant<HasSessionParameters>> {
        MultipartyGraduationTransition::new(
            vec![from],
            self.close_event(),
            self.successor_transition(),
        )
    }

    fn successor_transition(
        self,
    ) -> NextStateTransition<MultipartySessionEvent, Participant<HasSessionParameters>> {
        let context = ParticipantContext {
            directory: self.participant_context.directory,
            ohttp_keys: self.participant_context.ohttp_keys,
            session_parameters: self.session_parameters,
        };
        NextStateTransition::success(
            MultipartySessionEvent::SessionParametersAdopted(context.clone()),
            Participant::from_adopted_context(context),
        )
    }
}

/// Outcome of polling for session parameters before persistence.
#[derive(Debug)]
pub enum SessionParametersPollTransition {
    /// Directory has nothing yet; resume from the returned participant.
    Stasis(ParticipantAwaitingSessionParameters),
    /// Parameters retrieved; persist via [`SessionParametersPollTransition::save`].
    Adoption(ParticipantParametersAdoption),
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
        OptionalTransitionOutcome<R::Persister, ParticipantAwaitingSessionParameters>,
        GraduationError<R::Error, <R::Persister as SessionPersister>::InternalStorageError>,
    >
    where
        R: MultipartySessionRegistry,
        R::Persister: Clone,
    {
        match self {
            Self::Stasis(participant) => Ok(OptionalTransitionOutcome::Stasis(participant)),
            Self::Adoption(adoption) => {
                let (new, _) = adoption.graduation_transition(from.clone()).save(registry)?;
                Ok(OptionalTransitionOutcome::Progress(new))
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
            ParticipantAwaitingSessionParameters,
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

/// Errors from [`MultipartyGraduationTransition::save`].
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
