use bitcoin::transaction::{predict_weight, InputWeightPrediction};
use bitcoin::{FeeRate, ScriptBuf, Weight};
use concurrent_psbt::constructor::{BothModifiable, Constructor};
use concurrent_psbt::global::GlobalSortExt;
use concurrent_psbt::sort::{Deterministic, Sorter, Unset};
use psbt_v2::v2::Psbt;
use serde::{Deserialize, Serialize};

use super::plan::PlanBuilder;
use super::{ParticipantError, Plan};
use crate::multiparty::persist::EventfulTransition;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
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

    /// Whether [`balance`](Self::balance) exactly covers the network fee
    /// `min_feerate` requires for the accumulated PSBT's estimated weight.
    ///
    /// Deliberately an exact match, not `balance() >= required_fee`: an exact
    /// match from one participant's own partial view (its own fragments plus
    /// whatever it has read so far) is as good as impossible to hit by
    /// accident, so — like the old `balance() == 0` check it replaces — it
    /// still forces every participant to wait for the full pool rather than
    /// letting a participant whose own slice happens to be in surplus
    /// conclude it's done from a tiny, still-partial transaction. `>=` does
    /// not have this property: a participant that is a net payer relative to
    /// its own output can *always* trivially cover its own tiny local
    /// estimated fee alone, well before any peer fragment arrives.
    ///
    /// `None` if the weight can't yet be estimated (an input's scriptPubKey is
    /// not one of the types [`estimate_weight`] recognizes) — treated as
    /// "not balanced yet" by the caller rather than a hard error, since more
    /// directory fragments may still resolve it.
    ///
    /// TODO: this whole estimated-weight detour should be removed once the
    /// protocol grows pseudo-outputs. A pseudo-output makes the fee an
    /// explicit, negotiated output value instead of an off-band estimate every
    /// participant has to (re)compute identically pre-signing; `is_balanced`
    /// would then just be `balance() == 0` against a real output, and
    /// [`estimate_weight`] disappears entirely.
    fn is_balanced(&self, min_feerate: FeeRate) -> Option<bool> {
        let weight = estimate_weight(&self.accumulated_psbt())?;
        let required_fee = min_feerate.fee_wu(weight)?.to_sat() as i64;
        let balance = self.balance().to_sat();
        Some(balance == required_fee)
    }

    /// Whether every input in the accumulated PSBT carries a finalized witness.
    ///
    /// True once all participants (this one included) have broadcast their
    /// witnesses, i.e. the collaborative transaction is ready to extract.
    pub fn all_inputs_finalized(&self) -> bool { self.accumulated_psbt().is_finalized() }

    pub fn ready_to_sign_psbt(&self) -> Psbt {
        let mut psbt = Constructor::<BothModifiable, Unset>::try_from_psbt(self.accumulated_psbt())
            .unwrap()
            .into_inner();
        // TODO: Update to use actual sort seed.
        psbt.global.set_sort_seed(vec![0; 32]);
        let sorter: Sorter<Deterministic> = Sorter::from_unordered_psbt(psbt);
        sorter.into_ordered_psbt().expect("sort seed to be set")
    }

    /// The finalized collaborative transaction, ready to broadcast.
    ///
    /// Deterministically orders the accumulated PSBT (the same ordering the
    /// participants signed) — now carrying every input's witness — and extracts
    /// the network transaction. Requires [`all_inputs_finalized`](Self::all_inputs_finalized).
    pub fn final_tx(&self) -> bitcoin::Transaction {
        psbt_v2::v2::Extractor::new(self.ready_to_sign_psbt())
            .expect("all inputs finalized before extract")
            .extract_tx()
            .expect("finalized collaborative transaction extracts")
    }
}

/// Estimate the weight of the accumulated, not-yet-finalized collaborative
/// transaction from each input's spent scriptPubKey type and each output's
/// scriptPubKey length.
///
/// Returns `None` if any input's funding UTXO is missing or its scriptPubKey
/// isn't one of the types [`input_weight_prediction`] recognizes.
fn estimate_weight(psbt: &Psbt) -> Option<Weight> {
    let input_predictions = psbt
        .iter_funding_utxos()
        .map(|utxo| input_weight_prediction(&utxo.ok()?.script_pubkey))
        .collect::<Option<Vec<_>>>()?;
    let output_lens = psbt.outputs.iter().map(|output| output.script_pubkey.len());
    Some(predict_weight(input_predictions, output_lens))
}

/// Predict one input's weight from its scriptPubKey's address type, using the
/// worst-case (largest) signature size for each supported type.
///
/// Only the types with a fixed, pre-signing-known maximum witness/scriptSig
/// size are supported: P2WPKH, legacy P2PKH (compressed key), and P2TR
/// (key-path spend, the only kind this protocol produces). Anything else
/// (nested or bare P2SH/P2WSH, P2TR script-path) can't be sized before the
/// spending witness exists, so this returns `None` for those.
fn input_weight_prediction(script_pubkey: &ScriptBuf) -> Option<InputWeightPrediction> {
    if script_pubkey.is_p2wpkh() {
        Some(InputWeightPrediction::P2WPKH_MAX)
    } else if script_pubkey.is_p2tr() {
        Some(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH)
    } else if script_pubkey.is_p2pkh() {
        Some(InputWeightPrediction::P2PKH_COMPRESSED_MAX)
    } else {
        None
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
            ParticipantEvent::ActionPosted => self.record_action_posted(),
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

    /// Replay of [`MultipartySessionEvent::PlanActionPosted`]: advance the cursor.
    /// Never terminal — the plan is done only when the driver observes the
    /// segment's completion predicate and issues [`complete`](Self::complete).
    pub(crate) fn apply_action_posted(mut self, plan_cursor: usize) -> MultipartySession {
        self.state.plan_cursor = plan_cursor;
        MultipartySession::ParticipantHasPlan(self)
    }

    /// The plaintext PSBT fragment to post for the current plan action, or `None`
    /// once every action has been posted.
    pub fn next_action_fragment(&self) -> Option<Psbt> {
        self.state.plan.action(self.state.plan_cursor).map(|action| action.as_psbt_fragment())
    }

    /// Whether the plan has entered its witness segment.
    ///
    /// Derived from the plan's actions (a signed PSBT has been folded in), so the
    /// driver can tell a registration `HasPlan` from a witness one without a
    /// stored phase flag: registration → sign; witness → broadcast.
    pub fn is_witness_phase(&self) -> bool { self.state.0.plan.has_witness_actions() }

    /// Whether the current plan segment is finished.
    ///
    /// Requires the participant's own actions to be fully posted
    /// (`plan_cursor == plan.len()`), plus the segment's funding condition:
    /// registration is done when the accumulated PSBT's balance exactly covers
    /// the network fee `min_feerate` requires for its estimated weight (see
    /// [`is_balanced`](PlanPsbtAccumulator::is_balanced) for why this is an
    /// exact match rather than "at least"); the witness segment is done when
    /// every input carries a witness. The driver evaluates this on the
    /// replayed state (the authority) and, when true, either signs
    /// (registration) or finishes (witness). There is no completion event:
    /// both outcomes are re-derivable on replay, so only the non-derivable
    /// [`WitnessPlanGenerated`](MultipartySessionEvent::WitnessPlanGenerated) is
    /// logged.
    pub fn segment_complete(&self) -> bool {
        let accumulator = &self.state.0;
        if accumulator.plan_cursor < accumulator.plan.len() {
            return false;
        }
        if self.is_witness_phase() {
            accumulator.all_inputs_finalized()
        } else {
            let min_feerate = self.context.session_parameters.min_feerate();
            accumulator.is_balanced(min_feerate).unwrap_or(false)
        }
    }

    /// Fold the driver's signed PSBT back into the plan.
    ///
    /// Called on a registration `HasPlan` once [`segment_complete`](Self::segment_complete)
    /// holds. Appends one witness-broadcast action per owned input to the *same*
    /// plan (continuing its schedule) and stays in [`HasPlan`], now in the witness
    /// segment, so the driver paces and posts the witnesses. The grown plan is
    /// persisted so replay is deterministic.
    pub fn provide_signed_psbt(&self, signed_psbt: Psbt) -> ParticipantStepTransition {
        let plan = self.state.0.plan.append_witnesses(&signed_psbt);
        ParticipantStepTransition::success(
            [MultipartySessionEvent::WitnessPlanGenerated(plan.clone())],
            self.clone().apply_witness_plan(plan),
        )
    }

    /// Close the session once every input carries a witness.
    ///
    /// Called on a witness `HasPlan` after the driver has broadcast the finalized
    /// transaction ([`final_tx`](PlanPsbtAccumulator::final_tx)). There is no
    /// intermediate "ready to broadcast" state or event: readiness is derived from
    /// [`segment_complete`](Self::segment_complete) on the replayed fragments, and
    /// broadcasting is idempotent, so the only thing worth recording is the
    /// terminus. Emits [`MultipartySessionOutcome::Complete`].
    pub fn broadcast_complete(&self) -> ParticipantStepTransition {
        ParticipantStepTransition::success(
            [MultipartySessionEvent::Closed(MultipartySessionOutcome::Complete)],
            MultipartySession::Closed(MultipartySessionOutcome::Complete),
        )
    }

    /// Replay of [`MultipartySessionEvent::WitnessPlanGenerated`]: swap in the
    /// grown plan and resume plan execution at the witness segment.
    pub(crate) fn apply_witness_plan(self, plan: Plan) -> MultipartySession {
        let mut accumulator = self.state.0;
        accumulator.plan = plan;
        MultipartySession::ParticipantHasPlan(Participant {
            state: HasPlan(accumulator),
            context: self.context,
        })
    }

    /// Record that the current action's fragment was posted, advancing the cursor.
    ///
    /// Internal helper behind [`step`](Self::step)'s handling of
    /// [`ParticipantEvent::ActionPosted`]: the driver has confirmed the write, so
    /// this only advances the cursor and emits
    /// [`MultipartySessionEvent::PlanActionPosted`].
    pub(crate) fn record_action_posted(&self) -> ParticipantStepTransition {
        let mut accumulator = self.state.0.clone();
        accumulator.plan_cursor += 1;
        let plan_cursor = accumulator.plan_cursor;
        ParticipantStepTransition::success(
            [MultipartySessionEvent::PlanActionPosted(plan_cursor)],
            MultipartySession::ParticipantHasPlan(Participant {
                state: HasPlan(accumulator),
                context: self.context.clone(),
            }),
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

pub type PlanReadTransition =
    EventfulTransition<MultipartySessionEvent, Participant<HasPlan>, ParticipantError>;

/// A persist transition whose outcome is type-erased to [`MultipartySession`],
/// so a single persist command can carry any of the plan transitions regardless
/// of their concrete next-state type.
pub type ParticipantStepTransition =
    EventfulTransition<MultipartySessionEvent, MultipartySession, ParticipantError>;

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
                .save_event(MultipartySessionEvent::PlanActionPosted(cursor))
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
    fn step_action_posted_on_last_action_stays_has_plan() {
        let (persister, has_plan) = seeded(2, 1);

        let persist = has_plan.step(ParticipantEvent::ActionPosted);

        // Posting the final action is no longer terminal: HasPlan keeps reading
        // until the driver observes the segment's completion predicate.
        assert!(matches!(
            persist.save(&persister).expect("save"),
            MultipartySession::ParticipantHasPlan(_)
        ));
        match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) => assert_eq!(p.plan_cursor, 2),
            other => panic!("expected HasPlan, got {other:?}"),
        }
    }

    #[test]
    fn broadcast_complete_closes_the_session() {
        use crate::multiparty::session::MultipartySessionOutcome;

        // The witness segment is done; recording the broadcast closes the session.
        // (`broadcast_complete` records the terminus unconditionally; readiness is
        // the driver's call via `segment_complete`.)
        let (persister, has_plan) = seeded(1, 1);

        let session = has_plan.broadcast_complete().save(&persister).expect("save close");
        assert!(matches!(session, MultipartySession::Closed(MultipartySessionOutcome::Complete)));

        // Replay lands on the same terminal outcome — no readiness event needed.
        assert!(matches!(
            replay_event_log(&persister).expect("replay").0,
            MultipartySession::Closed(MultipartySessionOutcome::Complete)
        ));
    }

    /// A real P2WPKH scriptPubKey, so [`estimate_weight`] can size an input or
    /// output built from it — unlike the empty scripts [`sample_txout`] uses
    /// elsewhere.
    fn p2wpkh_script() -> bitcoin::ScriptBuf {
        use bitcoin::hashes::Hash;
        bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros())
    }

    /// A single P2WPKH `InputPair` funded with `value` sats.
    fn p2wpkh_input(value: u64) -> crate::receive::InputPair {
        use bitcoin::hashes::Hash;
        use bitcoin::psbt::Input as PsbtInput;
        use bitcoin::{OutPoint, TxIn, Txid, Weight};

        crate::receive::InputPair {
            txin: TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
                ..Default::default()
            },
            psbtin: PsbtInput {
                witness_utxo: Some(TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: p2wpkh_script(),
                }),
                ..Default::default()
            },
            expected_weight: Weight::ZERO,
        }
    }

    /// The exact fee `is_balanced` requires for a plan of `input_pairs` and
    /// `output_values`, all P2WPKH — computed the same way `is_balanced` does,
    /// so tests can hit its exact-match condition instead of guessing at a
    /// weight by hand.
    fn required_fee_for(input_values: &[u64], output_values: &[u64]) -> Amount {
        let mut builder = PlanBuilder::new();
        for value in input_values {
            builder = builder.add_input(p2wpkh_input(*value));
        }
        for value in output_values {
            builder = builder.add_output(TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: p2wpkh_script(),
            });
        }
        let mut accumulator = PlanPsbtAccumulator::new(builder.build());
        accumulator.plan_cursor = input_values.len() + output_values.len();

        let weight =
            super::estimate_weight(&accumulator.accumulated_psbt()).expect("weight estimable");
        sample_context().session_parameters.min_feerate().fee_wu(weight).expect("fee computable")
    }

    /// Post a plan's two actions one at a time, replaying between them so each
    /// `ActionPosted` event advances the persisted cursor from its actual
    /// current value rather than a stale in-memory copy.
    fn post_all_actions(
        persister: &InMemoryPersister<MultipartySessionEvent>,
        mut has_plan: Participant<HasPlan>,
        count: usize,
    ) -> Participant<HasPlan> {
        for _ in 0..count {
            has_plan.step(ParticipantEvent::ActionPosted).save(persister).expect("post");
            has_plan = match replay_event_log(persister).expect("replay").0 {
                MultipartySession::ParticipantHasPlan(p) => p,
                other => panic!("expected HasPlan, got {other:?}"),
            };
        }
        has_plan
    }

    #[test]
    fn segment_complete_registration_requires_full_post_and_exact_fee_balance() {
        // An output set exactly `required_fee_for`'s computed fee below the
        // input: registration is complete once both actions post, because the
        // balance matches the estimated fee exactly.
        let fee = required_fee_for(&[100_000], &[0]).to_sat();
        let output_value = 100_000 - fee;

        let plan = PlanBuilder::new()
            .add_input(p2wpkh_input(100_000))
            .add_output(TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: p2wpkh_script(),
            })
            .build();

        let persister = InMemoryPersister::<MultipartySessionEvent>::default();
        persister
            .save_event(MultipartySessionEvent::SessionParametersAdopted(sample_context()))
            .expect("save adopted");
        persister.save_event(MultipartySessionEvent::PlanGenerated(plan)).expect("save plan");
        let has_plan = match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) => p,
            other => panic!("expected HasPlan, got {other:?}"),
        };

        // Before both actions are posted (cursor 0 < len 2) the segment is not
        // done, regardless of balance.
        assert!(!has_plan.segment_complete());
        assert!(!has_plan.is_witness_phase());

        let has_plan = post_all_actions(&persister, has_plan, 2);
        // Posted (cursor == len) and balance exactly matches the estimated fee:
        // registration segment complete.
        assert!(has_plan.segment_complete());
        assert!(!has_plan.is_witness_phase());
    }

    #[test]
    fn segment_complete_registration_stays_incomplete_when_balance_off_the_exact_fee() {
        // A zero-fee-remaining balance (inputs == outputs) no longer completes
        // registration by itself: it covered the old zero-balance check, but
        // the estimated fee `min_feerate` now requires is nonzero, and
        // `is_balanced` requires an exact match — one sat over or under still
        // leaves the segment incomplete.
        let input = p2wpkh_input(10_000);
        let output = TxOut { value: Amount::from_sat(10_000), script_pubkey: p2wpkh_script() };
        let plan = PlanBuilder::new().add_input(input).add_output(output).build();

        let persister = InMemoryPersister::<MultipartySessionEvent>::default();
        persister
            .save_event(MultipartySessionEvent::SessionParametersAdopted(sample_context()))
            .expect("save adopted");
        persister.save_event(MultipartySessionEvent::PlanGenerated(plan)).expect("save plan");
        let has_plan = match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) => p,
            other => panic!("expected HasPlan, got {other:?}"),
        };

        let has_plan = post_all_actions(&persister, has_plan, 2);
        assert_eq!(has_plan.balance(), bitcoin::SignedAmount::ZERO);
        assert!(!has_plan.segment_complete(), "zero balance no longer covers the estimated fee");
    }

    #[test]
    fn segment_complete_stays_incomplete_when_weight_not_estimable() {
        // An input scriptPubKey outside the supported types (here, empty —
        // matching `sample_txout`/`balance_is_inputs_minus_outputs`'s
        // placeholder scripts) makes the weight, and so the required fee,
        // impossible to estimate. `is_balanced` returns `None` and
        // `segment_complete` must treat that as "not yet", not panic or
        // assume done, even though the raw balance covers the outputs.
        use bitcoin::hashes::Hash;
        use bitcoin::psbt::Input as PsbtInput;
        use bitcoin::{OutPoint, ScriptBuf, TxIn, Txid, Weight};

        let input = crate::receive::InputPair {
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

        let persister = InMemoryPersister::<MultipartySessionEvent>::default();
        persister
            .save_event(MultipartySessionEvent::SessionParametersAdopted(sample_context()))
            .expect("save adopted");
        persister.save_event(MultipartySessionEvent::PlanGenerated(plan)).expect("save plan");
        let has_plan = match replay_event_log(&persister).expect("replay").0 {
            MultipartySession::ParticipantHasPlan(p) => p,
            other => panic!("expected HasPlan, got {other:?}"),
        };

        let has_plan = post_all_actions(&persister, has_plan, 2);
        assert_eq!(has_plan.balance(), bitcoin::SignedAmount::from_sat(4_000));
        assert!(!has_plan.segment_complete());
    }
}
