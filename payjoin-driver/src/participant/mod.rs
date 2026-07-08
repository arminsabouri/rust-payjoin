//! Driver for a multiparty payjoin participant.
//!
//! The protocol logic lives in the `payjoin` state machine as a sans-io
//! [`step`](payjoin::multiparty::Participant::step): it takes a
//! [`ParticipantEvent`] and returns an ordered batch of [`ParticipantCommand`]s,
//! each either a state transition to persist or a fragment to broadcast. This
//! driver is the bridge: it performs the I/O the state machine cannot, feeds the
//! results back as events, and is the *sole* writer to the persister.
//!
//! Every mailbox write originates from a [`ParticipantCommand::Broadcast`], and
//! the driver processes the write's completion back through the state machine as
//! a [`ParticipantEvent::ActionPosted`], which hands back the state transition to
//! persist. Nothing bypasses `step`: even the first action is a
//! [`ParticipantEvent::Started`] command, so the driver never writes on its own
//! initiative.
//!
//! The loop consumes [`CollaborativeMessageSet::read`] as a stream of read rounds:
//! each poll long-polls when nothing is in flight yet, returning pending while
//! the request is outstanding so the executor can run other work. Each ready
//! batch (possibly empty) is fed to `step`, and every returned command is drained
//! before the next poll.

use std::collections::VecDeque;

use futures::TryStreamExt;
use payjoin::multiparty::{
    replay_event_log, HasPlan, MultipartySession, MultipartySessionEvent, Participant,
    ParticipantCommand, ParticipantEvent, ParticipantStep, Psbt,
};
use payjoin::persist::SessionPersister;

use crate::error::DriverError;
use crate::mailbox::CollaborativeMessageSet;

/// Drive a participant's plan to completion.
///
/// Bootstraps by posting the first action, then runs read rounds over `mailbox`,
/// persisting to `persister`, until the plan is fully executed.
pub async fn execute_plan<M, P>(mailbox: &M, persister: &P) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    // Bootstrap: post the first action. Replaying first means an already-executed
    // or undriveable session resolves without touching the mailbox. `Started` is
    // the state machine's kickoff, so even this first write goes through `step`.
    match load_has_plan(persister)? {
        None => return Ok(()),
        Some(has_plan) =>
            run_commands(mailbox, persister, has_plan, ParticipantEvent::Started).await?,
    }

    let mut messages = mailbox.read();
    loop {
        let Some(has_plan) = load_has_plan(persister)? else {
            break;
        };
        let fragments = match messages.try_next().await {
            Ok(Some(fragments)) => fragments,
            Ok(None) => return Err(DriverError::UnexpectedState),
            Err(error) => return Err(DriverError::Mailbox(Box::new(error))),
        };
        run_commands(mailbox, persister, has_plan, ParticipantEvent::FragmentsRead(fragments))
            .await?;
    }
    Ok(())
}

/// Replay the log into the live plan state, or `None` once the plan is executed.
fn load_has_plan<P>(persister: &P) -> Result<Option<Participant<HasPlan>>, DriverError>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let (session, _) = replay_event_log(persister)?;
    match session {
        MultipartySession::ParticipantHasPlan(has_plan) => Ok(Some(has_plan)),
        MultipartySession::ParticipantPlanExecuted(_) => Ok(None),
        _ => Err(DriverError::UnexpectedState),
    }
}

/// Feed `event` to `has_plan.step` and perform every returned command, in order,
/// before returning.
///
/// A [`ParticipantCommand::Broadcast`] is executed by writing the fragment and
/// then feeding the completed write back through the state machine as a
/// [`ParticipantEvent::ActionPosted`]; the resulting state transition (the cursor
/// advance) is enqueued and drained here too, so no write escapes without its
/// response being persisted. `current` tracks the live plan state a `Broadcast`
/// steps from: it starts as the participant `event` was stepped on, and each
/// `Persist` updates it to the persisted next state.
async fn run_commands<M, P>(
    mailbox: &M,
    persister: &P,
    has_plan: Participant<HasPlan>,
    event: ParticipantEvent,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let ParticipantStep { commands } = has_plan.step(event);
    let mut queue: VecDeque<ParticipantCommand> = commands.into();
    let mut current: Option<Participant<HasPlan>> = Some(has_plan);
    while let Some(command) = queue.pop_front() {
        match command {
            ParticipantCommand::Persist(transition) => {
                match transition.save(persister).map_err(|e| DriverError::Persist(e.to_string()))? {
                    MultipartySession::ParticipantHasPlan(has_plan) => current = Some(has_plan),
                    MultipartySession::ParticipantPlanExecuted(_) => current = None,
                    _ => return Err(DriverError::UnexpectedState),
                }
            }
            ParticipantCommand::Broadcast(fragment) => {
                mailbox.write(fragment).await.map_err(|e| DriverError::Mailbox(Box::new(e)))?;
                let has_plan = current.as_ref().ok_or(DriverError::UnexpectedState)?;
                queue.extend(has_plan.step(ParticipantEvent::ActionPosted).commands);
            }
        }
    }
    Ok(())
}
