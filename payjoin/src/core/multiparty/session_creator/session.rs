use serde::{Deserialize, Serialize};

use super::{CollectedSessions, ParametersDistributed, SessionCreator, SessionCreatorContext};
use crate::error::{InternalReplayError, ReplayError};
use crate::persist::SessionPersister;
use crate::{HpkePublicKey, ImplementationError};

fn replay_events(
    mut logs: impl Iterator<Item = SessionCreatorEvent>,
) -> Result<
    (SessionCreatorSession, SessionCreatorHistory),
    ReplayError<SessionCreatorSession, SessionCreatorEvent>,
> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut session = match first_event {
        SessionCreatorEvent::Created(context) => SessionCreatorSession::new(context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in logs {
        session_events.push(event.clone());
        session = session.process_event(event)?;
    }
    Ok((session, SessionCreatorHistory::new(session_events)))
}

/// Replay a session-creator event log to get the creator in its current state and history.
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<
    (SessionCreatorSession, SessionCreatorHistory),
    ReplayError<SessionCreatorSession, SessionCreatorEvent>,
>
where
    P: SessionPersister,
    P::SessionEvent: Into<SessionCreatorEvent> + Clone,
    P::SessionEvent: From<SessionCreatorEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    match replay_events(logs.map(|e| e.into())) {
        Ok(result) => Ok(result),
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            Err(e)
        }
    }
}

/// Events recorded during a multiparty session-creator session.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionCreatorEvent {
    Created(SessionCreatorContext),
    ParametersDeliveredTo(HpkePublicKey),
    Closed(SessionCreatorOutcome),
}

/// Outcome of a closed session-creator session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionCreatorOutcome {
    Failure,
}

/// Inferred status of a session-creator session from its event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCreatorStatus {
    Active,
    Failed,
    CollectingParameters,
    ParametersDistributed,
}

/// A collection of events from a session-creator session, from [`replay_event_log`].
#[derive(Debug, Clone)]
pub struct SessionCreatorHistory {
    #[allow(unused)]
    events: Vec<SessionCreatorEvent>,
}

impl SessionCreatorHistory {
    pub(crate) fn new(events: Vec<SessionCreatorEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

}

/// Type-erased session-creator session for replay and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCreatorSession {
    CollectedSessions(SessionCreator<CollectedSessions>),
    ParametersDistributed(SessionCreator<ParametersDistributed>),
    Closed(SessionCreatorOutcome),
}

impl SessionCreatorSession {
    fn new(context: SessionCreatorContext) -> Self {
        SessionCreatorSession::CollectedSessions(SessionCreator {
            state: CollectedSessions {},
            context,
        })
    }

    fn process_event(
        self,
        event: SessionCreatorEvent,
    ) -> Result<SessionCreatorSession, ReplayError<Self, SessionCreatorEvent>> {
        match (self, event) {
            (
                SessionCreatorSession::CollectedSessions(state),
                SessionCreatorEvent::ParametersDeliveredTo(recipient),
            ) => Ok(state.apply_parameters_delivered(recipient)),

            (_, SessionCreatorEvent::Closed(outcome)) => Ok(SessionCreatorSession::Closed(outcome)),

            (current_state, event) => Err(crate::error::InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}
