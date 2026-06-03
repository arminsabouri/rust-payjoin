//! Multiparty session events, state, replay, and history.

use serde::{Deserialize, Serialize};

use crate::error::{InternalReplayError, ReplayError};
use crate::multiparty::initiator::{
    HasReplyKey, Initialized as InitiatorInitialized, Initiator, InitiatorContext,
};
use crate::multiparty::responder::{
    Initialized as ResponderInitialized, Responder, ResponderContext, SentReplyKey,
};
use crate::multiparty::session_creator::{
    CollectedSessions, ParametersDistributed, SessionCreator, SessionCreatorContext,
};
use crate::persist::SessionPersister;
use crate::{HpkePublicKey, ImplementationError};

/// Multiparty session event log entry.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultipartySessionEvent {
    InitiatorCreated(InitiatorContext),
    InitiatorRetrievedReplyKey(HpkePublicKey),
    ResponderCreated(ResponderContext),
    ResponderSentReplyKey(HpkePublicKey),
    SessionCreatorCreated(SessionCreatorContext),
    SessionCreatorParametersDeliveredTo(HpkePublicKey),
    Closed(MultipartySessionOutcome),
}

/// Outcome when a multiparty session closes unsuccessfully.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultipartySessionOutcome {
    Failure,
}

impl MultipartySessionEvent {
    pub fn closed(outcome: MultipartySessionOutcome) -> Self { Self::Closed(outcome) }
}

/// Type-erased multiparty session state for replay and persistence.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartySession {
    InitiatorInitialized(Initiator<InitiatorInitialized>),
    InitiatorHasReplyKey(Initiator<HasReplyKey>),
    ResponderInitialized(Responder<ResponderInitialized>),
    ResponderSentReplyKey(Responder<SentReplyKey>),
    SessionCreatorCollectedSessions(SessionCreator<CollectedSessions>),
    SessionCreatorParametersDistributed(SessionCreator<ParametersDistributed>),
    Closed(MultipartySessionOutcome),
}

impl MultipartySession {
    pub fn is_pending_parameters(&self) -> bool {
        matches!(
            self,
            MultipartySession::InitiatorHasReplyKey(_)
                | MultipartySession::ResponderSentReplyKey(_)
        )
    }
}

impl MultipartySession {
    fn process_event(
        self,
        event: MultipartySessionEvent,
    ) -> Result<MultipartySession, ReplayError<Self, MultipartySessionEvent>> {
        match (self, event) {
            (
                MultipartySession::InitiatorInitialized(state),
                MultipartySessionEvent::InitiatorRetrievedReplyKey(reply_key),
            ) => Ok(state.apply_retrieved_reply_key(reply_key)),

            (
                MultipartySession::ResponderInitialized(state),
                MultipartySessionEvent::ResponderSentReplyKey(reply_key),
            ) => Ok(state.apply_sent_reply_key(reply_key)),

            (
                MultipartySession::SessionCreatorCollectedSessions(state),
                MultipartySessionEvent::SessionCreatorParametersDeliveredTo(recipient),
            ) => Ok(state.apply_parameters_delivered(recipient)),

            (_, MultipartySessionEvent::Closed(outcome)) => Ok(MultipartySession::Closed(outcome)),

            (current_state, event) => Err(InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}

fn replay_events<P>(
    persister: &P,
) -> Result<
    (MultipartySession, Vec<MultipartySessionEvent>),
    ReplayError<MultipartySession, MultipartySessionEvent>,
>
where
    P: SessionPersister,
    P::SessionEvent: Into<MultipartySessionEvent> + Clone,
{
    let events: Vec<MultipartySessionEvent> = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?
        .map(Into::into)
        .collect();

    let first_event = events.first().ok_or(InternalReplayError::NoEvents)?.clone();
    let mut session_events = vec![first_event.clone()];
    let mut session = match first_event {
        MultipartySessionEvent::InitiatorCreated(context) =>
            MultipartySession::InitiatorInitialized(Initiator {
                state: InitiatorInitialized {},
                context,
            }),
        MultipartySessionEvent::ResponderCreated(context) =>
            MultipartySession::ResponderInitialized(Responder {
                state: ResponderInitialized {},
                context,
            }),
        MultipartySessionEvent::SessionCreatorCreated(context) =>
            MultipartySession::SessionCreatorCollectedSessions(SessionCreator {
                state: CollectedSessions {},
                context,
            }),
        MultipartySessionEvent::Closed(outcome) => MultipartySession::Closed(outcome),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in events.into_iter().skip(1) {
        session_events.push(event.clone());
        session = session.process_event(event)?;
    }

    Ok((session, session_events))
}

fn construct_history(
    session_events: Vec<MultipartySessionEvent>,
) -> Result<SessionHistory, ReplayError<MultipartySession, MultipartySessionEvent>> {
    Ok(SessionHistory::new(session_events))
}

/// Replay a multiparty event log to get the session in its current state and history.
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<
    (MultipartySession, SessionHistory),
    ReplayError<MultipartySession, MultipartySessionEvent>,
>
where
    P: SessionPersister,
    P::SessionEvent: Into<MultipartySessionEvent> + Clone,
{
    let (session, session_events) = match replay_events(persister) {
        Ok(result) => result,
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    let history = construct_history(session_events)?;
    Ok((session, history))
}

/// Inferred status of a multiparty session from its event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    InitiatorActive,
    InitiatorHasReplyKey,
    ResponderActive,
    ResponderSentReplyKey,
    SessionCreatorCollectingParameters,
    SessionCreatorParametersDistributed,
    Closed(MultipartySessionOutcome),
}

/// A collection of events from a multiparty session, from [`replay_event_log`].
#[derive(Debug, Clone)]
pub struct SessionHistory {
    #[allow(unused)]
    events: Vec<MultipartySessionEvent>,
}

impl SessionHistory {
    pub(crate) fn new(events: Vec<MultipartySessionEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }
}
