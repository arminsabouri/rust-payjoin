//! Multiparty session events, state, replay, and history.

use core::fmt;

use concurrent_psbt::constructor::BothModifiable;
use concurrent_psbt::sort::Unset;
use psbt_v2::v2::Psbt;
use serde::{Deserialize, Serialize};

use crate::error::{InternalReplayError, ReplayError};
use crate::multiparty::initiator::{
    Initialized as InitiatorInitialized, Initiator, InitiatorContext,
};
use crate::multiparty::participant::{
    HasPlan, HasSessionParameters, Participant, ParticipantAwaitingSessionParameters,
    ParticipantContext, Plan, PlanExecuted, ReadyToExecutePlan,
};
use crate::multiparty::persist::MultipartySessionRegistry;
use crate::multiparty::responder::{
    Initialized as ResponderInitialized, Responder, ResponderContext,
};
use crate::multiparty::session_creator::{
    CollectedSessions, SessionCreator, SessionCreatorContext,
};
use crate::multiparty::SessionParameters;
use crate::persist::SessionPersister;
use crate::{HpkePublicKey, ImplementationError};

/// Multiparty session event log entry.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultipartySessionEvent {
    InitiatorCreated(InitiatorContext),
    InitiatorRetrievedReplyKey(HpkePublicKey),
    ResponderCreated(ResponderContext),
    ResponderSentReplyKey,
    /// First event of a post-graduation participant log.
    SessionParametersAdopted(ParticipantContext),
    /// Participant generated its initial plan from available inputs and payment obligations.
    PlanGenerated(Plan),
    /// Participant read and persisted one validated PSBT fragment from the shared directory.
    PlanDirectoryPsbtFragment(Psbt),
    /// Participant executed a plan action and advanced to this cursor.
    PlanExecuted(usize),
    SessionCreatorCreated(SessionCreatorContext),
    SessionCreatorParametersDeliveredTo(HpkePublicKey),
    /// Session parameters were acknowledged by every committed participant.
    SessionCreatorAllParametersDelivered,
    Closed(MultipartySessionOutcome),
}

/// Outcome when a multiparty session closes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MultipartySessionOutcome {
    /// Session failed before completing the protocol.
    Failure,
    /// Pre-parameters phase complete; session parameters continue in a new log.
    Graduated(SessionParameters),
}

impl MultipartySessionEvent {
    pub fn closed(outcome: MultipartySessionOutcome) -> Self { Self::Closed(outcome) }
}

/// Type-erased multiparty session state for replay and persistence.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartySession {
    InitiatorInitialized(Initiator<InitiatorInitialized>),
    ResponderInitialized(Responder<ResponderInitialized>),
    ParticipantAwaitingSessionParameters(ParticipantAwaitingSessionParameters),
    ParticipantHasSessionParameters(Participant<HasSessionParameters>),
    ParticipantHasPlan(Participant<HasPlan>),
    ParticipantReadyToExecutePlan(Participant<ReadyToExecutePlan>),
    ParticipantPlanExecuted(Participant<PlanExecuted>),
    SessionCreatorCollectedSessions(SessionCreator<CollectedSessions>),
    Closed(MultipartySessionOutcome),
}

impl MultipartySession {
    pub fn is_pending_parameters(&self) -> bool {
        matches!(self, MultipartySession::ParticipantAwaitingSessionParameters(_))
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
                MultipartySessionEvent::ResponderSentReplyKey,
            ) => Ok(state.apply_sent_reply_key()),

            (
                MultipartySession::SessionCreatorCollectedSessions(state),
                MultipartySessionEvent::SessionCreatorParametersDeliveredTo(recipient),
            ) => Ok(state.apply_parameters_delivered(recipient)),

            (
                MultipartySession::SessionCreatorCollectedSessions(state),
                MultipartySessionEvent::SessionCreatorAllParametersDelivered,
            ) => Ok(state.apply_all_parameters_delivered()),

            (
                MultipartySession::ParticipantHasSessionParameters(state),
                MultipartySessionEvent::PlanGenerated(plan),
            ) => Ok(state.apply_with_plan(plan)),

            (
                MultipartySession::ParticipantHasPlan(state),
                MultipartySessionEvent::PlanDirectoryPsbtFragment(directory_psbt_fragment),
            ) => Ok(state.apply_directory_psbt_fragment(directory_psbt_fragment)),

            (
                MultipartySession::ParticipantHasPlan(state),
                MultipartySessionEvent::PlanExecuted(plan_cursor),
            ) => Ok(state.apply_with_plan_cursor(plan_cursor)),

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
        MultipartySessionEvent::SessionParametersAdopted(context) =>
            MultipartySession::ParticipantHasSessionParameters(Participant::from_adopted_context(
                context,
            )),
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

/// Errors from [`collect_open_sessions_awaiting_parameters`].
pub enum CollectAwaitingParametersError<R: MultipartySessionRegistry> {
    Registry(R::Error),
    Replay(ReplayError<MultipartySession, MultipartySessionEvent>),
}

impl<R: MultipartySessionRegistry> fmt::Debug for CollectAwaitingParametersError<R>
where
    R::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(err) => f.debug_tuple("Registry").field(err).finish(),
            Self::Replay(err) => f.debug_tuple("Replay").field(err).finish(),
        }
    }
}

impl<R: MultipartySessionRegistry> fmt::Display for CollectAwaitingParametersError<R>
where
    R::Error: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(err) => write!(f, "registry error: {err}"),
            Self::Replay(err) => write!(f, "replay error: {err}"),
        }
    }
}

impl<R: MultipartySessionRegistry> std::error::Error for CollectAwaitingParametersError<R>
where
    R::Error: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            Self::Replay(err) => Some(err),
        }
    }
}

/// Replay every open session in `registry` and return those awaiting session parameters.
///
/// Empty logs and sessions still in initiator/responder bootstrap are skipped. Replay failures
/// other than an empty log are returned immediately.
pub fn collect_open_sessions_awaiting_parameters_with_persisters<R>(
    registry: &R,
) -> Result<
    Vec<(&R::Persister, ParticipantAwaitingSessionParameters)>,
    CollectAwaitingParametersError<R>,
>
where
    R: MultipartySessionRegistry,
{
    let mut awaiting = Vec::new();

    for persister in registry.list_open().map_err(CollectAwaitingParametersError::Registry)? {
        let (session, _) = match replay_events(persister) {
            Ok(result) => result,
            Err(err) if err.is_no_events() => continue,
            Err(err) => return Err(CollectAwaitingParametersError::Replay(err)),
        };

        if let MultipartySession::ParticipantAwaitingSessionParameters(participant) = session {
            awaiting.push((persister, participant));
        }
    }

    Ok(awaiting)
}

/// Like [`collect_open_sessions_awaiting_parameters_with_persisters`], without persister handles.
pub fn collect_open_sessions_awaiting_parameters<R>(
    registry: &R,
) -> Result<Vec<ParticipantAwaitingSessionParameters>, CollectAwaitingParametersError<R>>
where
    R: MultipartySessionRegistry,
{
    collect_open_sessions_awaiting_parameters_with_persisters(registry)
        .map(|entries| entries.into_iter().map(|(_, participant)| participant).collect())
}

/// Inferred status of a multiparty session from its event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    InitiatorActive,
    ResponderActive,
    ParticipantAwaitingSessionParameters,
    ParticipantHasSessionParameters,
    ParticipantHasPlan,
    ParticipantReadyToExecutePlan,
    ParticipantPlanExecuted,
    SessionCreatorCollectingParameters,
    Closed(MultipartySessionOutcome),
}

/// A collection of events from a multiparty session, from [`replay_event_log`].
#[derive(Debug, Clone)]
pub struct SessionHistory {
    events: Vec<MultipartySessionEvent>,
}

impl SessionHistory {
    pub(crate) fn new(events: Vec<MultipartySessionEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

    /// Validated PSBT fragments read from the shared session mailbox.
    pub fn directory_psbt_fragments(&self) -> impl Iterator<Item = &Psbt> {
        self.events.iter().filter_map(|event| match event {
            MultipartySessionEvent::PlanDirectoryPsbtFragment(fragment) => Some(fragment),
            _ => None,
        })
    }

    /// Number of validated PSBT fragments already persisted from the shared session mailbox.
    pub fn directory_psbt_fragment_count(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event, MultipartySessionEvent::PlanDirectoryPsbtFragment(_)))
            .count()
    }

    /// PSBT fragments this participant sent to the shared session mailbox.
    pub fn sent_psbt_fragments(&self) -> Vec<Psbt> {
        let mut plan = None;
        let mut sent_cursor = 0;
        let mut fragments = Vec::new();

        for event in &self.events {
            match event {
                MultipartySessionEvent::PlanGenerated(next_plan) => {
                    plan = Some(next_plan);
                    sent_cursor = 0;
                }
                MultipartySessionEvent::PlanExecuted(plan_cursor) =>
                    if let Some(plan) = plan {
                        let next_cursor = (*plan_cursor).min(plan.len());
                        for index in sent_cursor..next_cursor {
                            if let Some(action) = plan.action(index) {
                                fragments.push(action.as_psbt_fragment());
                            }
                        }
                        sent_cursor = next_cursor;
                    },
                _ => {}
            }
        }

        fragments
    }

    pub fn accumulated_psbt(&self) -> Psbt {
        let mut psbt = concurrent_psbt::constructor::Creator::new().build();
        // First add our own psbt fragments
        for fragment in self.sent_psbt_fragments() {
            let parsed =
                concurrent_psbt::constructor::Constructor::<BothModifiable, Unset>::try_from_psbt(
                    fragment,
                )
                .unwrap();
            // TODO: deal with error
            psbt = psbt.try_join(parsed).try_unwrap().unwrap();
        }

        for fragment in self.directory_psbt_fragments() {
            let parsed =
                concurrent_psbt::constructor::Constructor::<BothModifiable, Unset>::try_from_psbt(
                    fragment.clone(),
                )
                .expect("persisted directory PSBT fragments are validated at intake");
            // TODO: deal with error
            psbt = psbt.try_join(parsed).try_unwrap().expect("joining validated PSBT fragments");
        }

        psbt.into_psbt()
    }
}

#[cfg(test)]
mod tests {
    use concurrent_psbt::constructor::Creator;
    use psbt_v2::v2::Psbt;

    use super::{MultipartySessionEvent, SessionHistory};

    #[test]
    fn session_history_returns_directory_psbt_fragments_in_order() {
        let first = Creator::new().build().into_psbt();
        let second = Creator::new().build().into_psbt();
        let history = SessionHistory {
            events: vec![
                MultipartySessionEvent::ResponderSentReplyKey,
                MultipartySessionEvent::PlanDirectoryPsbtFragment(first.clone()),
                MultipartySessionEvent::PlanDirectoryPsbtFragment(second.clone()),
            ],
        };

        let fragments: Vec<Psbt> = history.directory_psbt_fragments().cloned().collect();

        assert_eq!(fragments, vec![first, second]);
        assert_eq!(history.directory_psbt_fragment_count(), 2);
    }
}
