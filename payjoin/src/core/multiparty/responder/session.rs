use serde::{Deserialize, Serialize};

use super::{Initialized, Responder, ResponderContext, SentReplyKey};
use crate::error::{InternalReplayError, ReplayError};
use crate::persist::SessionPersister;
use crate::{HpkePublicKey, ImplementationError};

fn replay_events(
    mut logs: impl Iterator<Item = ResponderEvent>,
) -> Result<(ResponderSession, ResponderHistory), ReplayError<ResponderSession, ResponderEvent>> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut session = match first_event {
        ResponderEvent::Created(context) => ResponderSession::new(context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in logs {
        session_events.push(event.clone());
        session = session.process_event(event)?;
    }
    Ok((session, ResponderHistory::new(session_events)))
}

/// Replay a responder event log to get the responder in its current state and history.
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(ResponderSession, ResponderHistory), ReplayError<ResponderSession, ResponderEvent>>
where
    P: SessionPersister,
    P::SessionEvent: Into<ResponderEvent> + Clone,
    P::SessionEvent: From<ResponderEvent>,
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

/// Events recorded during a multiparty responder session.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponderEvent {
    Created(ResponderContext),
    SentReplyKey(HpkePublicKey),
    Closed(ResponderOutcome),
}

/// Outcome of a closed responder session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponderOutcome {
    Failure,
}

/// Inferred status of a responder session from its event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderStatus {
    Active,
    Failed,
    SentReplyKey,
}

/// A collection of events from a responder session, from [`replay_event_log`].
#[derive(Debug, Clone)]
pub struct ResponderHistory {
    events: Vec<ResponderEvent>,
}

impl ResponderHistory {
    pub(crate) fn new(events: Vec<ResponderEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

    fn session_context(&self) -> ResponderContext {
        let mut context = self
            .events
            .iter()
            .find_map(|event| match event {
                ResponderEvent::Created(ctx) => Some(ctx.clone()),
                _ => None,
            })
            .expect("Session event log must contain a Created event");

        context.sent_reply_key = self.events.iter().find_map(|event| match event {
            ResponderEvent::SentReplyKey(key) => Some(key.clone()),
            _ => None,
        });

        context
    }

    /// Reply public key written to the initiator mailbox, if the responder has sent one.
    pub fn reply_key(&self) -> Option<HpkePublicKey> {
        self.session_context().sent_reply_key.clone()
    }

    /// Inferred status of the session.
    pub fn status(&self) -> ResponderStatus {
        match self.events.last() {
            Some(ResponderEvent::Closed(ResponderOutcome::Failure)) => ResponderStatus::Failed,
            Some(ResponderEvent::SentReplyKey(_)) => ResponderStatus::SentReplyKey,
            _ => ResponderStatus::Active,
        }
    }
}

/// Type-erased responder session for replay and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderSession {
    Initialized(Responder<Initialized>),
    SentReplyKey(Responder<SentReplyKey>),
    Closed(ResponderOutcome),
}

impl ResponderSession {
    fn new(context: ResponderContext) -> Self {
        ResponderSession::Initialized(Responder { state: Initialized {}, context })
    }

    fn process_event(
        self,
        event: ResponderEvent,
    ) -> Result<ResponderSession, ReplayError<Self, ResponderEvent>> {
        match (self, event) {
            (ResponderSession::Initialized(state), ResponderEvent::SentReplyKey(reply_key)) =>
                Ok(state.apply_sent_reply_key(reply_key)),

            (_, ResponderEvent::Closed(outcome)) => Ok(ResponderSession::Closed(outcome)),

            (current_state, event) => Err(crate::error::InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}
