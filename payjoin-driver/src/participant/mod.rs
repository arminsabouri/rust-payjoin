//! Driver for a multiparty payjoin participant.
//!
//! The protocol logic lives in the `payjoin` state machine as a sans-io
//! [`step`](payjoin::multiparty::Participant::step): it takes a
//! [`ParticipantEvent`] and returns the single state transition to persist. This
//! driver is the bridge: it performs the I/O the state machine cannot, feeds the
//! results back as events, and is the *sole* writer to the persister.
//!
//! Two effect sources drive the loop, and neither lives in the state machine:
//!
//! - **Inbound** — [`CollaborativeMessageSet::read`] yields read rounds. Each
//!   ready batch (possibly empty) is fed to `step` as
//!   [`ParticipantEvent::FragmentsRead`], which persists the fragments.
//! - **Outbound** — [`Schedule::due_actions`] yields plan indices as their
//!   `send_at` offset elapses (a Poisson cadence), so posts are paced rather than
//!   fired as fast as the mailbox can be read. When an action is due the driver
//!   asks the state machine for the fragment via
//!   [`next_action_fragment`](payjoin::multiparty::Participant::next_action_fragment),
//!   writes it, then reports the completed write back as
//!   [`ParticipantEvent::ActionPosted`] — the transition that advances the
//!   cursor. The schedule only decides *when*; the state machine still decides
//!   *what*.
//!
//! There is a single authoritative cursor (`plan_cursor`, persisted). The
//! schedule stream is seeded from it once and holds only an ephemeral view, so
//! the two cannot durably drift.

use futures::future::{select, Either};
use futures::StreamExt;
use payjoin::multiparty::{
    replay_event_log, HasPlan, MultipartySession, MultipartySessionEvent, Participant,
    ParticipantEvent, ParticipantStepTransition, Psbt,
};
use payjoin::persist::SessionPersister;

use crate::error::DriverError;
use crate::mailbox::CollaborativeMessageSet;
use crate::schedule::Schedule;

/// Drive a participant's plan to completion.
///
/// Concurrently services inbound mailbox reads and the outbound action schedule,
/// persisting to `persister`, until the plan is fully executed.
pub async fn execute_plan<M, S, P>(
    mailbox: &M,
    schedule: &S,
    persister: &P,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    S: Schedule,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let Some(has_plan) = load_has_plan(persister)? else {
        return Ok(());
    };

    // The plan (and its send_at schedule) is fixed for the whole execution; clone
    // it once so the schedule stream can read the offsets for the loop's lifetime.
    let plan = has_plan.plan().clone();
    let mut reads = mailbox.read();
    // Seed the schedule from the single authoritative cursor; on a resumed plan
    // this skips the already-posted prefix.
    let mut due = schedule.due_actions(&plan, has_plan.plan_cursor());
    let mut schedule_done = false;

    loop {
        let Some(has_plan) = load_has_plan(persister)? else {
            break;
        };

        if schedule_done {
            let fragments = read_item(reads.next().await)?;
            step_read(persister, has_plan, fragments)?;
            continue;
        }

        match select(reads.next(), due.next()).await {
            Either::Left((read, _)) => {
                let fragments = read_item(read)?;
                step_read(persister, has_plan, fragments)?;
            }
            Either::Right((None, _)) => schedule_done = true,
            Either::Right((Some(due), _)) => {
                due.map_err(|e| DriverError::Schedule(Box::new(e)))?;
                post_next_action(mailbox, persister, has_plan).await?;
            }
        }
    }
    Ok(())
}

/// Translate a mailbox read stream item into the fragments it carries.
fn read_item<E>(item: Option<Result<Vec<Psbt>, E>>) -> Result<Vec<Psbt>, DriverError>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match item {
        Some(Ok(fragments)) => Ok(fragments),
        Some(Err(error)) => Err(DriverError::Mailbox(Box::new(error))),
        None => Err(DriverError::UnexpectedState),
    }
}

/// Persist a read round: record the inbound fragments, no broadcast.
fn step_read<P>(
    persister: &P,
    has_plan: Participant<HasPlan>,
    fragments: Vec<Psbt>,
) -> Result<(), DriverError>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    save(persister, has_plan.step(ParticipantEvent::FragmentsRead(fragments)))
}

/// Post the current plan action, then advance the cursor.
///
/// The schedule already decided this action is due; the state machine supplies
/// the fragment. After the write is durable we report [`ParticipantEvent::ActionPosted`],
/// whose transition advances the single authoritative cursor.
async fn post_next_action<M, P>(
    mailbox: &M,
    persister: &P,
    has_plan: Participant<HasPlan>,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let fragment = has_plan.next_action_fragment().ok_or(DriverError::UnexpectedState)?;
    mailbox.write(fragment).await.map_err(|e| DriverError::Mailbox(Box::new(e)))?;
    save(persister, has_plan.step(ParticipantEvent::ActionPosted))
}

/// Persist one state transition, checking the resulting session stays advanceable.
fn save<P>(persister: &P, transition: ParticipantStepTransition) -> Result<(), DriverError>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    match transition.save(persister).map_err(|e| DriverError::Persist(e.to_string()))? {
        MultipartySession::ParticipantHasPlan(_)
        | MultipartySession::ParticipantPlanExecuted(_) => Ok(()),
        _ => Err(DriverError::UnexpectedState),
    }
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
