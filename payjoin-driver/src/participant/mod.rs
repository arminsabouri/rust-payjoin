//! Drivers for a multiparty payjoin participant.
//!
//! Two entities run concurrently over the same [`CollaborativeMessageSet`],
//! wired by an mpsc channel — but only one of them touches the state machine:
//!
//! - [`network::run_network_task`] — a **dumb reader**: it reads the shared
//!   mailbox (the adapter decrypts and parses frames into fragments) and forwards
//!   the new ones. No persister, no protocol state.
//! - [`run_actor`] — the **actor**: the *sole* owner of the state machine and the
//!   *sole* writer to the persister. It persists the forwarded fragments, replies
//!   with the authoritative persisted count, (stub) re-evaluates the plan, and
//!   posts its own actions.
//!
//! [`execute_plan`] wires the channel and runs both to completion.

pub mod network;

use futures::channel::mpsc::{self, UnboundedReceiver};
use futures::StreamExt;
use payjoin::multiparty::{
    replay_event_log, HasPlan, MultipartySession, MultipartySessionEvent, Participant,
    PlanExecution, Psbt,
};
use payjoin::persist::SessionPersister;

use self::network::{run_network_task, FragmentBatch};
use crate::error::DriverError;
use crate::mailbox::CollaborativeMessageSet;

/// Drive a participant's plan to completion: run the dumb
/// [`network::run_network_task`] reader and the [`run_actor`] state-machine
/// driver concurrently over `mailbox`, persisting to `persister`.
pub async fn execute_plan<M, P>(mailbox: &M, persister: &P) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let (batches_tx, batches_rx) = mpsc::unbounded();

    let (actor_result, network_result) = futures::future::join(
        run_actor(mailbox, persister, batches_rx),
        run_network_task(mailbox, batches_tx),
    )
    .await;

    actor_result?;
    network_result?;
    Ok(())
}

/// Run the actor: the sole state-machine driver and persister writer.
///
/// For each batch from the network task it replays the log, persists the new
/// fragments, replies with the authoritative persisted count, (stub)
/// re-evaluates, then posts its next action. When the network task ends it posts
/// any remaining actions without waiting.
pub async fn run_actor<M, P>(
    mailbox: &M,
    persister: &P,
    mut batches: UnboundedReceiver<FragmentBatch>,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    while let Some(batch) = batches.next().await {
        let (session, history) = replay_event_log(persister)?;
        let has_plan = match session {
            MultipartySession::ParticipantHasPlan(participant) => participant,
            MultipartySession::ParticipantPlanExecuted(_) => {
                let _ = batch.ack.send(history.directory_psbt_fragment_count());
                return Ok(());
            }
            _ => return Err(DriverError::UnexpectedState),
        };

        let persisted_before = history.directory_psbt_fragment_count();
        if !batch.fragments.is_empty() {
            has_plan
                .record_fragments(&batch.fragments)
                .save(persister)
                .map_err(|e| DriverError::Persist(e.to_string()))?;
        }
        // Reply with the authoritative persisted count so the network task only
        // forwards genuinely new fragments next time.
        let _ = batch.ack.send(persisted_before + batch.fragments.len());
        re_evaluate_plan(&has_plan, &batch.fragments);

        if post_next_action(mailbox, persister, &has_plan).await? {
            return Ok(());
        }
    }

    // Network task ended: finish posting any remaining actions.
    post_remaining_actions(mailbox, persister).await
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

/// Post remaining actions to completion without waiting on the network task.
async fn post_remaining_actions<M, P>(mailbox: &M, persister: &P) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    loop {
        let (session, _) = replay_event_log(persister)?;
        let has_plan = match session {
            MultipartySession::ParticipantHasPlan(participant) => participant,
            MultipartySession::ParticipantPlanExecuted(_) => return Ok(()),
            _ => return Err(DriverError::UnexpectedState),
        };
        if post_next_action(mailbox, persister, &has_plan).await? {
            return Ok(());
        }
    }
}

/// Re-evaluate (prune / re-choose) the plan in light of newly read fragments.
///
/// STUB: currently a no-op. When plan re-evaluation lands, this is where the
/// actor will inspect the fragments and decide whether to switch to a cheaper /
/// more private branch of its plan.
fn re_evaluate_plan(_has_plan: &Participant<HasPlan>, _fragments: &[Psbt]) {
    // Intentionally empty. See the doc comment above.
}
