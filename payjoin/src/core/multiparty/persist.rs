//! Multiparty session registry for a coordinator wallet (initiator / session creator).
//!
//! Each protocol session has its own [`crate::persist::SessionPersister`] event log (one log per
//! initiator bootstrap, per responder bootstrap, per creator distribution, …). Only the
//! coordinator needs a [`MultipartySessionRegistry`]: it registers handles for every log it
//! orchestrates (including responders' logs in tests and integrated apps) and uses
//! [`crate::multiparty::collect_open_sessions_awaiting_parameters`] to find participants ready
//! for session parameters.

use core::fmt;
use std::error;

use crate::multiparty::participant::{AwaitingSessionParameters, Participant};
use crate::multiparty::session::{MultipartySessionEvent, MultipartySessionOutcome};
use crate::multiparty::SessionParameters;
use crate::persist::{InMemoryPersister, MaybeFatalTransitionWithNoResults, SessionPersister};

/// Index of many multiparty session persisters.
pub trait MultipartySessionRegistry {
    /// Registry-level errors (not per-log storage errors).
    type Error: error::Error + Send + Sync + 'static;
    /// Concrete persister type returned for a handle.
    type Persister: SessionPersister<SessionEvent = MultipartySessionEvent>;

    /// Handles for session logs that are not closed.
    fn list_open(&self) -> Result<Vec<&Self::Persister>, Self::Error>;

    /// Create new session
    /// TODO: do we want to link the previous session wiht the new one?
    /// TODO: does not need to be mut. Use interior mutability for the inmemory registry.
    fn new_session(&mut self) -> Result<Self::Persister, Self::Error>;

    /// Close `from` with [`MultipartySessionOutcome::Graduated`].
    fn close_graduated(
        &mut self,
        from: &Self::Persister,
        graduation: &SessionParametersGraduation,
    ) -> Result<
        (),
        GraduationError<Self::Error, <Self::Persister as SessionPersister>::InternalStorageError>,
    > {
        from.save_event(graduation.close_event()).map_err(GraduationError::Storage)?;
        from.close().map_err(GraduationError::Storage)?;
        Ok(())
    }

    /// Close `from` with [`MultipartySessionOutcome::Graduated`], then register a new log
    /// whose first event is [`MultipartySessionEvent::SessionParametersAdopted`].
    fn save_graduation(
        &mut self,
        from: &Self::Persister,
        graduation: SessionParametersGraduation,
    ) -> Result<
        Self::Persister,
        GraduationError<Self::Error, <Self::Persister as SessionPersister>::InternalStorageError>,
    > {
        self.close_graduated(from, &graduation)?;
        let new = self.new_session().map_err(GraduationError::Registry)?;
        new.save_event(graduation.adopted_event()).map_err(GraduationError::Storage)?;
        Ok(new)
    }
}

/// Successful end of a pre-parameters log: close with [`MultipartySessionOutcome::Graduated`]
/// and continue in a new log whose first event carries the adopted session parameters.
/// TODO: this is masquerading as a transition. Fine for now, when we consider upstreaming changes
/// we should change this to match the paradigm in the rest of the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionParametersGraduation {
    session_parameters: SessionParameters,
}

impl SessionParametersGraduation {
    pub(crate) fn new(session_parameters: SessionParameters) -> Self { Self { session_parameters } }

    /// Session parameters adopted into the post-graduation log.
    pub fn session_parameters(&self) -> &SessionParameters { &self.session_parameters }

    pub(crate) fn close_event(&self) -> MultipartySessionEvent {
        MultipartySessionEvent::Closed(MultipartySessionOutcome::Graduated(
            self.session_parameters.clone(),
        ))
    }

    pub(crate) fn adopted_event(&self) -> MultipartySessionEvent {
        MultipartySessionEvent::SessionParametersAdopted(self.session_parameters.clone())
    }
}

/// Outcome of polling for session parameters before persistence.
#[derive(Debug)]
pub enum SessionParametersPollTransition {
    /// Directory has nothing yet; resume from the returned participant.
    Stasis(Participant<AwaitingSessionParameters>),
    /// Parameters retrieved; persist via [`SessionParametersPollTransition::save`].
    Graduation(SessionParametersGraduation),
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
    /// Stasis requires no registry mutation. Graduation closes `from` and registers a new log
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
            Self::Graduation(graduation) => {
                let new = registry.save_graduation(from, graduation)?;
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

/// Errors from [`MultipartySessionRegistry::save_graduation`].
#[derive(Debug)]
pub enum GraduationError<R, S> {
    Registry(R),
    Storage(S),
}

impl<R: fmt::Display, S: fmt::Display> fmt::Display for GraduationError<R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(err) => write!(f, "registry error: {err}"),
            Self::Storage(err) => write!(f, "storage error: {err}"),
        }
    }
}

impl<R, S> error::Error for GraduationError<R, S>
where
    R: error::Error + 'static,
    S: error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            Self::Storage(err) => Some(err),
        }
    }
}

/// Errors from [`InMemoryMultipartyRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No session is registered under this handle.
    NotFound(SessionId),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "multiparty session not found: {:?}", id),
        }
    }
}

impl error::Error for RegistryError {}

/// Opaque identifier for one persisted multiparty session log.
///
/// The registry assigns handles; the library does not embed protocol semantics in the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

/// In-memory registry for tests and prototyping.
///
/// Use [`InMemoryMultipartyRegistry::create_session`] to register a new empty log, then pass
/// the returned [`SessionId`] into transition `.save(&registry.persister(&id)?)` flows.
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
