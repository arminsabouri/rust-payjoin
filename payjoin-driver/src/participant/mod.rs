//! Driver for a multiparty payjoin participant.
//!
//! A single task owns the state machine and is the *sole* writer to the
//! persister. It is expressed as a stream of driver steps
//! ([`stream::try_unfold`]) rather than an inner loop: each step replays the
//! log, persists the fragments read by the previous step, re-evaluates the plan
//! in their light, posts the next action, then long-polls the mailbox for the
//! fragments the *next* step will persist. The stream ends when the plan is
//! fully executed.
//!
//! Reading and processing happen in the same step, so there is one writer, no
//! channel, and no cross-task cursor to keep in sync. The read blocks
//! server-side (a long poll) until a fragment past the persisted cursor exists,
//! so the driver is naturally paced without a client-side timer and stays
//! portable (FFI, WASM).

use futures::{future, stream, TryStreamExt};
use payjoin::multiparty::{
    replay_event_log, HasPlan, MultipartySession, MultipartySessionEvent, Participant,
    PlanExecution, Psbt,
};
use payjoin::persist::SessionPersister;

use crate::error::DriverError;
use crate::mailbox::CollaborativeMessageSet;

/// Drive a participant's plan to completion.
///
/// Runs the participant driver as a stream of steps over `mailbox`, persisting
/// to `persister`, until the plan is fully executed.
pub async fn execute_plan<M, P>(mailbox: &M, persister: &P) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    // Each step carries the fragments read by the previous step. The seed is
    // empty, so the first action posts without a spurious initial read.
    let steps = stream::try_unfold(Vec::<Psbt>::new(), move |pending| async move {
        drive_step(mailbox, persister, pending).await
    });
    steps.try_for_each(|()| future::ready(Ok(()))).await
}

/// Run one step of the participant driver.
///
/// Persists `pending` (the fragments the previous step read), re-evaluates the
/// plan, and posts the next action. Returns `None` once the plan is fully
/// executed; otherwise `Some(((), next))` where `next` are the fragments the
/// following step will persist, long-polled past the persisted cursor.
async fn drive_step<M, P>(
    mailbox: &M,
    persister: &P,
    pending: Vec<Psbt>,
) -> Result<Option<((), Vec<Psbt>)>, DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let (session, _) = replay_event_log(persister)?;
    let has_plan = match session {
        MultipartySession::ParticipantHasPlan(has_plan) => has_plan,
        MultipartySession::ParticipantPlanExecuted(_) => return Ok(None),
        _ => return Err(DriverError::UnexpectedState),
    };

    // Persist the fragments read by the previous step, then re-evaluate the plan
    // in their light. The persisted cursor for the next read advances by exactly
    // the fragments we just recorded.
    let persisted_before = has_plan.directory_psbt_fragment_count();
    if !pending.is_empty() {
        has_plan
            .record_fragments(&pending)
            .save(persister)
            .map_err(|e| DriverError::Persist(e.to_string()))?;
    }
    let persisted = persisted_before + pending.len();
    re_evaluate_plan(&has_plan, &pending);

    // Post the next action. If that completes the plan, the stream ends.
    if post_next_action(mailbox, persister, &has_plan).await? {
        return Ok(None);
    }

    // The plan needs more fragments from the directory. Long-poll past what we
    // have persisted; the read blocks server-side until something new lands.
    let next: Vec<Psbt> = mailbox
        .read(persisted)
        .try_collect()
        .await
        .map_err(|e| DriverError::Mailbox(Box::new(e)))?;

    Ok(Some(((), next)))
}

/// Post the current plan action, if any. Returns `true` once the plan is fully
/// executed.
async fn post_next_action<M, P>(
    mailbox: &M,
    persister: &P,
    has_plan: &Participant<HasPlan>,
) -> Result<bool, DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let Some(fragment) = has_plan.next_action_fragment() else {
        return Ok(true);
    };
    mailbox.write(fragment).await.map_err(|e| DriverError::Mailbox(Box::new(e)))?;
    match has_plan
        .record_action_posted()
        .save(persister)
        .map_err(|e| DriverError::Persist(e.to_string()))?
    {
        PlanExecution::NeedsDirectoryRead(_) => Ok(false),
        PlanExecution::Executed(_) => Ok(true),
    }
}

/// Re-evaluate (prune / re-choose) the plan in light of newly read fragments.
///
/// STUB: currently a no-op. When plan re-evaluation lands, this is where the
/// driver will inspect the fragments and decide whether to switch to a cheaper /
/// more private branch of its plan.
fn re_evaluate_plan(_has_plan: &Participant<HasPlan>, _fragments: &[Psbt]) {
    // Intentionally empty. See the doc comment above.
}
