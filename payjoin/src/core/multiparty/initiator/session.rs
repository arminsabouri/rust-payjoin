use serde::{Deserialize, Serialize};

use super::{HasReplyKey, Initialized, Initiator, InitiatorContext};
use crate::error::{InternalReplayError, ReplayError};
use crate::persist::SessionPersister;
use crate::{HpkePublicKey, ImplementationError};

fn replay_events(
    mut logs: impl Iterator<Item = InitiatorEvent>,
) -> Result<(InitiatorSession, InitiatorHistory), ReplayError<InitiatorSession, InitiatorEvent>> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut session = match first_event {
        InitiatorEvent::Created(context) => InitiatorSession::new(context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in logs {
        session_events.push(event.clone());
        session = session.process_event(event)?;
    }
    Ok((session, InitiatorHistory::new(session_events)))
}

/// Replay an initiator event log to get the initiator in its current state and history.
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(InitiatorSession, InitiatorHistory), ReplayError<InitiatorSession, InitiatorEvent>>
where
    P: SessionPersister,
    P::SessionEvent: Into<InitiatorEvent> + Clone,
    P::SessionEvent: From<InitiatorEvent>,
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

/// Events recorded during a multiparty initiator session.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InitiatorEvent {
    Created(InitiatorContext),
    RetrievedReplyKey(HpkePublicKey),
    Closed(InitiatorOutcome),
}

/// Outcome of a closed initiator session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InitiatorOutcome {
    Failure,
}

/// Inferred status of an initiator session from its event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitiatorStatus {
    Active,
    Failed,
    HasReplyKey,
}

/// A collection of events from an initiator session, from [`replay_event_log`].
#[derive(Debug, Clone)]
pub struct InitiatorHistory {
    events: Vec<InitiatorEvent>,
}

impl InitiatorHistory {
    pub(crate) fn new(events: Vec<InitiatorEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

    fn session_context(&self) -> InitiatorContext {
        let mut context = self
            .events
            .iter()
            .find_map(|event| match event {
                InitiatorEvent::Created(ctx) => Some(ctx.clone()),
                _ => None,
            })
            .expect("Session event log must contain a Created event");

        context.reply_key = self.events.iter().find_map(|event| match event {
            InitiatorEvent::RetrievedReplyKey(key) => Some(key.clone()),
            _ => None,
        });

        context
    }

    /// Reply key from the session, if the initiator has received one.
    pub fn reply_key(&self) -> Option<HpkePublicKey> { self.session_context().reply_key.clone() }

    /// Inferred status of the session.
    pub fn status(&self) -> InitiatorStatus {
        match self.events.last() {
            Some(InitiatorEvent::Closed(InitiatorOutcome::Failure)) => InitiatorStatus::Failed,
            Some(InitiatorEvent::RetrievedReplyKey(_)) => InitiatorStatus::HasReplyKey,
            _ => InitiatorStatus::Active,
        }
    }
}

/// Type-erased initiator session for replay and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitiatorSession {
    Initialized(Initiator<Initialized>),
    HasReplyKey(Initiator<HasReplyKey>),
    Closed(InitiatorOutcome),
}

impl InitiatorSession {
    fn new(context: InitiatorContext) -> Self {
        InitiatorSession::Initialized(Initiator { state: Initialized {}, context })
    }

    fn process_event(
        self,
        event: InitiatorEvent,
    ) -> Result<InitiatorSession, ReplayError<Self, InitiatorEvent>> {
        match (self, event) {
            (
                InitiatorSession::Initialized(state),
                InitiatorEvent::RetrievedReplyKey(reply_key),
            ) => Ok(state.apply_retrieved_reply_key(reply_key)),

            (_, InitiatorEvent::Closed(outcome)) => Ok(InitiatorSession::Closed(outcome)),

            (current_state, event) => Err(crate::error::InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}
