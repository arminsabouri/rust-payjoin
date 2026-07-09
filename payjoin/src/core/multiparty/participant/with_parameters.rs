use concurrent_psbt::constructor::{BothModifiable, Constructor, OutputsModifiable};
use concurrent_psbt::global::GlobalSortExt;
use concurrent_psbt::sort::{Deterministic, Sorter, Unset};
use psbt_v2::v2::Psbt;
use serde::{Deserialize, Serialize};

use super::plan::PlanBuilder;
use super::{ParticipantError, Plan};
use crate::multiparty::persist::EventfulTransition;
use crate::multiparty::session::{MultipartySession, MultipartySessionEvent};
use crate::multiparty::session_parameters::SessionParameters;
use crate::persist::NextStateTransition;
use crate::receive::InputPair;
use crate::{OhttpKeys, Url};

/// Persistent context for a multiparty participant after adopting session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantContext {
    pub(crate) directory: Url,
    pub ohttp_keys: OhttpKeys,
    pub(crate) session_parameters: SessionParameters,
}

/// Multiparty participant state machine (post role bootstrap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant<State> {
    pub(crate) state: State,
    pub(crate) context: ParticipantContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasSessionParameters {}

impl Participant<HasSessionParameters> {
    pub(crate) fn from_adopted_context(context: ParticipantContext) -> Self {
        Self { state: HasSessionParameters {}, context }
    }

    pub fn session_parameters(&self) -> &SessionParameters { &self.context.session_parameters }

    pub(crate) fn apply_with_plan(self, plan: Plan) -> MultipartySession {
        MultipartySession::ParticipantHasPlan(Participant {
            state: HasPlan(PlanPsbtAccumulator::new(plan)),
            context: self.context,
        })
    }

    // Next state should be one where we generate our plan:
    // What actions are we going to take in the "best worst" case
    // `HasPlan` state then iterates over available actions while reading from the directory and persisting others' actions
    // We do want to save the first plan we come up with. And as we learn new information from others we will prune the plan and pick
    // a better branch of the decision tree -- based on some cost / privacy metric.

    pub fn generate_plan(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
        payment_obligations: impl IntoIterator<Item = bitcoin::TxOut>,
    ) -> NextStateTransition<MultipartySessionEvent, Participant<HasPlan>> {
        let mut plan = PlanBuilder::new();
        for input in candidate_inputs {
            plan = plan.add_input(input);
        }
        for output in payment_obligations {
            plan = plan.add_output(output);
        }
        let plan = plan.build();
        NextStateTransition::success(
            MultipartySessionEvent::PlanGenerated(plan.clone()),
            Participant {
                state: HasPlan(PlanPsbtAccumulator::new(plan)),
                context: self.context.clone(),
            },
        )
    }
}

/// PSBT fragments collected while executing a participant plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPsbtAccumulator {
    pub(crate) plan: Plan,
    pub(crate) plan_cursor: usize,
    pub(crate) directory_psbt_fragments: Vec<Psbt>,
}

impl PlanPsbtAccumulator {
    pub(crate) fn new(plan: Plan) -> Self {
        Self { plan, plan_cursor: 0, directory_psbt_fragments: vec![] }
    }

    pub(crate) fn into_executed(mut self) -> Self {
        self.plan_cursor = self.plan.len();
        self
    }

    /// The participant's plan, including each action's `send_at` schedule offset.
    pub fn plan(&self) -> &Plan { &self.plan }

    /// Number of plan actions already posted to the shared mailbox — the index of
    /// the next action to send.
    pub fn plan_cursor(&self) -> usize { self.plan_cursor }

    /// PSBT fragments this participant sent to the shared session mailbox.
    pub fn sent_psbt_fragments(&self) -> impl Iterator<Item = Psbt> + '_ {
        (0..self.plan_cursor.min(self.plan.len()))
            .filter_map(|index| self.plan.action(index).map(|action| action.as_psbt_fragment()))
    }

    /// Validated PSBT fragments read from the shared session mailbox.
    pub fn directory_psbt_fragments(&self) -> impl Iterator<Item = &Psbt> + '_ {
        self.directory_psbt_fragments.iter()
    }

    /// Number of validated PSBT fragments already persisted from the shared session mailbox.
    pub fn directory_psbt_fragment_count(&self) -> usize { self.directory_psbt_fragments.len() }

    pub fn accumulated_psbt(&self) -> Psbt {
        let mut psbt = concurrent_psbt::constructor::Creator::new().build();
        for fragment in self.sent_psbt_fragments() {
            let parsed = Constructor::<BothModifiable, Unset>::try_from_psbt(fragment).unwrap();
            // TODO: deal with error
            psbt = psbt.try_join(parsed).try_unwrap().unwrap();
        }

        for fragment in self.directory_psbt_fragments() {
            let parsed = Constructor::<BothModifiable, Unset>::try_from_psbt(fragment.clone())
                .expect("persisted directory PSBT fragments are validated at intake");
            // TODO: deal with error
            psbt = psbt.try_join(parsed).try_unwrap().expect("joining validated PSBT fragments");
        }

        psbt.into_psbt()
    }

    /// Net value the accumulated PSBT has available to pay the network fee:
    /// the sum of every input's value minus the sum of every output's value
    /// (`inputs - outputs`).
    ///
    /// The user-facing goal is a "balance of 0" — the point at which the inputs
    /// cover the outputs *and* the network fee exactly. This returns the pre-fee
    /// delta, so that balanced state is reached once the returned amount equals
    /// the required fee. A negative value means the outputs registered so far
    /// are not yet covered by the inputs at all.
    ///
    /// Input amounts come from each input's funding UTXO, which the participant
    /// now carries in its input fragments (see `psbt_v2_input`).
    ///
    /// TODO: fold in the network fee. Once weight estimation for a partially
    /// accumulated multiparty PSBT exists, add an `is_balanced()` that returns
    /// true when `balance() - min_feerate * estimated_weight == 0` (a true zero
    /// balance). No such weight model exists yet, so for now the caller compares
    /// this delta against a fee it computes itself.
    pub fn balance(&self) -> bitcoin::SignedAmount {
        let psbt = self.accumulated_psbt();
        // TODO: surface, rather than panic on, a peer fragment that omits its
        // funding UTXO. Intake validation does not yet guarantee every input
        // carries its value, so a malformed peer input can panic here.
        let inputs: u64 = psbt
            .iter_funding_utxos()
            .map(|utxo| utxo.expect("accumulated input carries its funding UTXO").value.to_sat())
            .sum();
        let outputs: u64 = psbt.outputs.iter().map(|output| output.amount.to_sat()).sum();
        // Total bitcoin value is bounded well within i64, so neither cast wraps.
        bitcoin::SignedAmount::from_sat(inputs as i64 - outputs as i64)
    }

    pub fn ready_to_sign_psbt(&self) -> Psbt {
        let mut psbt =
            Constructor::<OutputsModifiable, Unset>::try_from_psbt(self.accumulated_psbt())
                .unwrap()
                .into_inner();
        // TODO: Update to use actual sort seed.
        psbt.global.set_sort_seed(vec![0; 32]);
        let sorter: Sorter<Deterministic> = Sorter::from_unordered_psbt(psbt);
        sorter.into_ordered_psbt().expect("sort seed to be set")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasPlan(pub(crate) PlanPsbtAccumulator);

impl std::ops::Deref for HasPlan {
    type Target = PlanPsbtAccumulator;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::DerefMut for HasPlan {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl std::ops::Deref for Participant<HasPlan> {
    type Target = PlanPsbtAccumulator;

    fn deref(&self) -> &Self::Target { &self.state.0 }
}

/// An input to the participant plan state machine.
///
/// The state machine is sans-io: it never performs transport itself, so an event
/// only ever reports that some I/O the driver performed on the machine's behalf
/// has completed.
#[derive(Debug, Clone)]
pub enum ParticipantEvent {
    /// The fragment we last broadcast was durably written to the shared mailbox.
    ActionPosted,
    /// The validated PSBT fragments read from the shared mailbox this round, past
    /// the persisted cursor. The driver reads one round at a time, so this is the
    /// whole batch a single read produced.
    FragmentsRead(Vec<Psbt>),
}

impl Participant<HasPlan> {
    /// Advance the plan state machine in response to one [`ParticipantEvent`],
    /// returning the single state transition to persist.
    ///
    /// This is the single entry point for state transitions: it subsumes the
    /// lower-level `record_*` methods and decides, purely from protocol state,
    /// what to persist next.
    ///
    /// Both events are persist-only. Inbound reads and outbound broadcasts are
    /// decoupled: [`ParticipantEvent::FragmentsRead`] only records the fragments
    /// read from the shared mailbox. Broadcasting is driven separately by the
    /// driver's schedule (each action posted at its `send_at` offset); the driver
    /// obtains the fragment from
    /// [`next_action_fragment`](Self::next_action_fragment), writes it, and
    /// reports the completed write back as [`ParticipantEvent::ActionPosted`],
    /// which advances the cursor.
    pub fn step(&self, event: ParticipantEvent) -> ParticipantStepTransition {
        match event {
            ParticipantEvent::ActionPosted =>
                self.record_action_posted().map_outcome(MultipartySession::from),
            ParticipantEvent::FragmentsRead(fragments) =>
                self.record_fragments(&fragments).map_outcome(MultipartySession::from),
        }
    }

    pub(crate) fn apply_directory_psbt_fragment(
        mut self,
        directory_psbt_fragment: Psbt,
    ) -> MultipartySession {
        self.state.directory_psbt_fragments.push(directory_psbt_fragment);
        MultipartySession::ParticipantHasPlan(self)
    }

    pub(crate) fn apply_with_plan_cursor(mut self, plan_cursor: usize) -> MultipartySession {
        if plan_cursor >= self.state.plan.len() {
            return MultipartySession::ParticipantPlanExecuted(Participant {
                state: PlanExecuted(self.state.0.clone().into_executed()),
                context: self.context,
            });
        }
        self.state.plan_cursor = plan_cursor;
        MultipartySession::ParticipantHasPlan(self)
    }

    /// The plaintext PSBT fragment to post for the current plan action, or `None`
    /// once every action has been posted.
    pub fn next_action_fragment(&self) -> Option<Psbt> {
        self.state.plan.action(self.state.plan_cursor).map(|action| action.as_psbt_fragment())
    }

    /// Record that the current action's fragment was posted to the shared
    /// mailbox, advancing the plan.
    ///
    /// Internal helper behind [`step`](Self::step)'s handling of
    /// [`ParticipantEvent::ActionPosted`]: the driver has confirmed the write, so
    /// this only advances the cursor and emits the
    /// [`MultipartySessionEvent::PlanExecuted`] event.
    pub(crate) fn record_action_posted(&self) -> PlanExecutionTransition {
        let mut psbt_accumulator = self.state.0.clone();
        let plan_cursor = psbt_accumulator.plan_cursor + 1;
        psbt_accumulator.plan_cursor = plan_cursor;

        let execution = if plan_cursor >= psbt_accumulator.plan.len() {
            PlanExecution::Executed(Participant {
                state: PlanExecuted(psbt_accumulator.into_executed()),
                context: self.context.clone(),
            })
        } else {
            PlanExecution::NeedsDirectoryRead(Participant {
                state: HasPlan(psbt_accumulator),
                context: self.context.clone(),
            })
        };

        PlanExecutionTransition::success(
            [MultipartySessionEvent::PlanExecuted(plan_cursor)],
            execution,
        )
    }

    /// Persist validated PSBT fragments read from the shared mailbox.
    ///
    /// Internal helper behind [`step`](Self::step)'s handling of
    /// [`ParticipantEvent::FragmentsRead`]: the mailbox adapter has already
    /// decrypted *and parsed* these fragments, and the driver reads only the ones
    /// past the persisted count (which it learns from
    /// [`directory_psbt_fragment_count`](PlanPsbtAccumulator::directory_psbt_fragment_count)).
    /// So this simply appends one
    /// [`MultipartySessionEvent::PlanDirectoryPsbtFragment`] per fragment — no
    /// positional dedup of raw frames, which is what previously let an invalid
    /// frame cause a valid fragment to be re-recorded.
    pub(crate) fn record_fragments(&self, fragments: &[Psbt]) -> PlanReadTransition {
        let events = fragments
            .iter()
            .cloned()
            .map(MultipartySessionEvent::PlanDirectoryPsbtFragment)
            .collect::<Vec<_>>();
        PlanReadTransition::success(events, self.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExecution {
    NeedsDirectoryRead(Participant<HasPlan>),
    Executed(Participant<PlanExecuted>),
}

impl From<PlanExecution> for MultipartySession {
    fn from(execution: PlanExecution) -> Self {
        match execution {
            PlanExecution::NeedsDirectoryRead(state) =>
                MultipartySession::ParticipantHasPlan(state),
            PlanExecution::Executed(state) => MultipartySession::ParticipantPlanExecuted(state),
        }
    }
}

pub type PlanReadTransition =
    EventfulTransition<MultipartySessionEvent, Participant<HasPlan>, ParticipantError>;

/// A persist transition whose outcome is type-erased to [`MultipartySession`],
/// so a single persist command can carry any of the plan transitions regardless
/// of their concrete next-state type.
pub type ParticipantStepTransition =
    EventfulTransition<MultipartySessionEvent, MultipartySession, ParticipantError>;

// TODO: evaluate if we want stronger state transition types than just PlanExecution. In the current use case we just have two states: current and next
// And rn I can't think of any other states we would end up in from process a post res
pub type PlanExecutionTransition =
    EventfulTransition<MultipartySessionEvent, PlanExecution, ParticipantError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExecuted(pub(crate) PlanPsbtAccumulator);

impl std::ops::Deref for PlanExecuted {
    type Target = PlanPsbtAccumulator;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::ops::Deref for Participant<PlanExecuted> {
    type Target = PlanPsbtAccumulator;

    fn deref(&self) -> &Self::Target { &self.state.0 }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, FeeRate, Sequence, TxOut};
    use concurrent_psbt::constructor::Creator;

    use super::{HasPlan, Participant, ParticipantContext, ParticipantEvent, PlanPsbtAccumulator};
    use crate::multiparty::participant::plan::PlanBuilder;
    use crate::multiparty::session::{MultipartySession, MultipartySessionEvent};
    use crate::multiparty::session_parameters::{InputScriptType, SessionParameters};
    use crate::multiparty::{replay_event_log, test_helpers};
    use crate::persist::{InMemoryPersister, SessionPersister};

    #[test]
    fn plan_psbt_accumulator_returns_directory_psbt_fragments_in_order() {
        let first = Creator::new().build().into_psbt();
        let second = Creator::new().build().into_psbt();
        let mut accumulator = PlanPsbtAccumulator::new(PlanBuilder::new().build());
        accumulator.directory_psbt_fragments = vec![first.clone(), second.clone()];

        let fragments: Vec<_> = accumulator.directory_psbt_fragments().cloned().collect();

        assert_eq!(fragments, vec![first, second]);
        assert_eq!(accumulator.directory_psbt_fragment_count(), 2);
    }

    fn sample_context() -> ParticipantContext {
        ParticipantContext {
            directory: crate::Url::parse("https://example.com").expect("valid url"),
            ohttp_keys: test_helpers::test_ohttp_keys(),
            session_parameters: SessionParameters::new(
                Version::TWO,
                LockTime::ZERO,
                FeeRate::from_sat_per_vb(1).expect("valid feerate"),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                vec![InputScriptType::P2wpkh],
                None,
            ),
        }
    }

    fn sample_txout() -> TxOut {
        TxOut { value: Amount::from_sat(10_000), script_pubkey: bitcoin::ScriptBuf::new() }
    }

    /// Seed a persister with a `plan_len`-action plan advanced to `cursor`, then
    /// replay it into a live `Participant<HasPlan>`.
    fn seeded(
        plan_len: usize,
        cursor: usize,
    ) -> (InMemoryPersister<MultipartySessionEvent>, Participant<HasPlan>) {
        let mut builder = PlanBuilder::new();
        for _ in 0..plan_len {
            builder = builder.add_output(sample_txout());
        }
        let persister = InMemoryPersister::default();
        persister
            .save_event(MultipartySessionEvent::SessionParametersAdopted(sample_context()))
            .expect("save adopted");
        persister
            .save_event(MultipartySessionEvent::PlanGenerated(builder.build()))
            .expect("save plan");
        if cursor > 0 {
            persister
                .save_event(MultipartySessionEvent::PlanExecuted(cursor))
                .expect("save cursor");
        }
        match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(participant) => (persister, participant),
            other => panic!("expected HasPlan, got {other:?}"),
        }
    }

    #[test]
    fn balance_is_inputs_minus_outputs() {
        use bitcoin::hashes::Hash;
        use bitcoin::psbt::Input as PsbtInput;
        use bitcoin::{OutPoint, ScriptBuf, SignedAmount, TxIn, Txid, Weight};

        use crate::receive::InputPair;

        // A single 10_000 sat input carried with its funding UTXO, and a 6_000
        // sat output — leaving 4_000 sat of value for the fee.
        let input = InputPair {
            txin: TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
                ..Default::default()
            },
            psbtin: PsbtInput {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::new(),
                }),
                ..Default::default()
            },
            expected_weight: Weight::ZERO,
        };
        let output = TxOut { value: Amount::from_sat(6_000), script_pubkey: ScriptBuf::new() };
        let plan = PlanBuilder::new().add_input(input).add_output(output).build();

        let mut accumulator = PlanPsbtAccumulator::new(plan);
        // Mark both actions posted so they contribute to the accumulated PSBT.
        accumulator.plan_cursor = 2;

        assert_eq!(accumulator.balance(), SignedAmount::from_sat(4_000));
    }

    #[test]
    fn step_fragments_read_persists_the_read() {
        let (persister, has_plan) = seeded(2, 0);

        // FragmentsRead is persist-only: it records the read and never broadcasts.
        let persist = has_plan
            .step(ParticipantEvent::FragmentsRead(vec![Creator::new().build().into_psbt()]));

        // Saving the persist appends one directory fragment and stays HasPlan.
        assert!(matches!(
            persist.save(&persister).expect("save"),
            MultipartySession::ParticipantHasPlan(_)
        ));
        match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) =>
                assert_eq!(p.directory_psbt_fragment_count(), 1),
            other => panic!("expected HasPlan, got {other:?}"),
        }
    }

    #[test]
    fn step_empty_fragments_read_records_nothing() {
        let (persister, has_plan) = seeded(2, 0);

        // An empty read still steps, but records no directory fragments.
        let persist = has_plan.step(ParticipantEvent::FragmentsRead(vec![]));

        assert!(matches!(
            persist.save(&persister).expect("save"),
            MultipartySession::ParticipantHasPlan(_)
        ));
        match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) =>
                assert_eq!(p.directory_psbt_fragment_count(), 0),
            other => panic!("expected HasPlan, got {other:?}"),
        }
    }

    #[test]
    fn step_action_posted_advances_the_cursor_and_stays_has_plan() {
        let (persister, has_plan) = seeded(2, 0);

        let persist = has_plan.step(ParticipantEvent::ActionPosted);

        assert!(matches!(
            persist.save(&persister).expect("save"),
            MultipartySession::ParticipantHasPlan(_)
        ));
        match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) => assert_eq!(p.plan_cursor, 1),
            other => panic!("expected HasPlan, got {other:?}"),
        }
    }

    #[test]
    fn step_action_posted_on_last_action_reaches_terminal() {
        let (persister, has_plan) = seeded(2, 1);

        let persist = has_plan.step(ParticipantEvent::ActionPosted);

        // Posting the final action graduates to the terminal executed state.
        assert!(matches!(
            persist.save(&persister).expect("save"),
            MultipartySession::ParticipantPlanExecuted(_)
        ));
        assert!(matches!(
            replay_event_log(&persister).expect("replay").0,
            MultipartySession::ParticipantPlanExecuted(_)
        ));
    }
}
