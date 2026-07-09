//! Driver for a multiparty payjoin participant.
//!
//! The protocol logic lives in the `payjoin` state machine as a sans-io
//! [`step`](payjoin::multiparty::Participant::step): it takes a
//! [`ParticipantEvent`] and returns the single state transition to persist. This
//! driver is the bridge: it performs the I/O the state machine cannot, feeds the
//! results back as events, and is the *sole* writer to the persister.
//!
//! Three effect sources drive the loop, and none lives in the state machine:
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
//! - **Signing** — once registration balances to zero the driver hands the
//!   sorted [`ready_to_sign_psbt`](payjoin::multiparty::PlanPsbtAccumulator::ready_to_sign_psbt)
//!   to the caller's [`Signer`] and folds the result back via
//!   [`provide_signed_psbt`](payjoin::multiparty::Participant::provide_signed_psbt),
//!   which grows the plan with one witness-broadcast action per owned input.
//!
//! The plan runs in two segments — registration, then (after signing) witnesses —
//! sharing one [`HasPlan`] state and one authoritative cursor (`plan_cursor`,
//! persisted). The driver derives the phase and the segment's completion from the
//! replayed state ([`segment_complete`](payjoin::multiparty::Participant::segment_complete),
//! [`is_witness_phase`](payjoin::multiparty::Participant::is_witness_phase)); only
//! the non-derivable grown plan is logged. Each segment gets a **fresh** schedule
//! stream seeded from the current cursor, so growing the plan simply re-enters the
//! paced loop with a new stream — the stream is never mutated in place.

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
use crate::signer::Signer;

/// Drive a participant's plan through registration, signing, and witness
/// broadcast, until the collaborative transaction is ready to extract.
///
/// Returns once every input carries a witness; the caller extracts the finalized
/// transaction from the replayed state
/// ([`final_tx`](payjoin::multiparty::PlanPsbtAccumulator::final_tx)). Broadcasting
/// it to the bitcoin network is out of scope.
pub async fn execute_plan<M, S, G, P>(
    mailbox: &M,
    schedule: &S,
    signer: &G,
    persister: &P,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    S: Schedule,
    G: Signer,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    loop {
        let has_plan = load_has_plan(persister)?;

        if !has_plan.segment_complete() {
            // Pace and post the current segment until it is funded (registration)
            // or fully witnessed. A fresh schedule stream, seeded from the current
            // cursor, is built inside — so the witness segment gets its own stream.
            run_segment(mailbox, schedule, persister, &has_plan).await?;
            continue;
        }

        if has_plan.is_witness_phase() {
            // Every witness is in: the collaborative transaction is ready to
            // extract. Broadcasting to the p2p network is out of scope here.
            return Ok(());
        }

        // Registration balanced to zero: sign the accumulated PSBT and fold the
        // witnesses back in, growing the plan into its witness segment.
        let signed_psbt = signer
            .sign(has_plan.ready_to_sign_psbt())
            .await
            .map_err(|e| DriverError::Sign(Box::new(e)))?;
        save(persister, has_plan.provide_signed_psbt(signed_psbt))?;
    }
}

/// Pace and post one plan segment, servicing reads concurrently, until the
/// segment's completion predicate holds (funded, or fully witnessed).
async fn run_segment<M, S, P>(
    mailbox: &M,
    schedule: &S,
    persister: &P,
    has_plan: &Participant<HasPlan>,
) -> Result<(), DriverError>
where
    M: CollaborativeMessageSet<Message = Psbt>,
    S: Schedule,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    // The plan is fixed for this segment; seed a fresh schedule from the
    // authoritative cursor (skipping the already-posted prefix on a resume, or the
    // whole registration prefix in the witness segment).
    let plan = has_plan.plan().clone();
    let mut reads = mailbox.read();
    let mut due = schedule.due_actions(&plan, has_plan.plan_cursor());
    let mut schedule_done = false;

    loop {
        let has_plan = load_has_plan(persister)?;
        if has_plan.segment_complete() {
            return Ok(());
        }

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
///
/// Every plan transition — posting, reading, and folding in the signed PSBT —
/// stays in [`HasPlan`]; the registration and witness segments share it.
fn save<P>(persister: &P, transition: ParticipantStepTransition) -> Result<(), DriverError>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    match transition.save(persister).map_err(|e| DriverError::Persist(e.to_string()))? {
        MultipartySession::ParticipantHasPlan(_) => Ok(()),
        _ => Err(DriverError::UnexpectedState),
    }
}

/// Replay the log into the live plan state.
fn load_has_plan<P>(persister: &P) -> Result<Participant<HasPlan>, DriverError>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let (session, _) = replay_event_log(persister)?;
    match session {
        MultipartySession::ParticipantHasPlan(has_plan) => Ok(has_plan),
        _ => Err(DriverError::UnexpectedState),
    }
}
