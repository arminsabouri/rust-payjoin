use concurrent_psbt::constructor::{BothModifiable, Constructor, OutputsModifiable};
use concurrent_psbt::global::GlobalSortExt;
use concurrent_psbt::sort::{Deterministic, Sorter, Unset};
use psbt_v2::v2::Psbt;
use serde::{Deserialize, Serialize};

use super::plan::PlanBuilder;
use super::{ParticipantError, Plan};
use crate::hpke::HpkeKeyPair;
use crate::multiparty::persist::EventfulTransition;
use crate::multiparty::session::{MultipartySession, MultipartySessionEvent};
use crate::multiparty::session_parameters::SessionParameters;
use crate::persist::NextStateTransition;
use crate::receive::InputPair;
use crate::uri::ShortId;
use crate::{OhttpKeys, Url};

/// Persistent context for a multiparty participant after adopting session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantContext {
    pub(crate) directory: Url,
    pub ohttp_keys: OhttpKeys,
    pub(crate) session_parameters: SessionParameters,
}

impl ParticipantContext {
    fn session_shared_keypair(&self) -> HpkeKeyPair {
        self.session_parameters.session_shared_keypair()
    }

    fn session_shared_mailbox_id(&self) -> ShortId {
        self.session_shared_keypair().public_key().short_id()
    }
}

/// Session keys a mailbox adapter needs to reach the shared mailbox.
///
/// Handed out by [`Participant::shared_mailbox_coordinates`] so the adapter can
/// own OHTTP encapsulation and HPKE — no transport or crypto lives in the state
/// machine.
#[derive(Debug, Clone)]
pub struct SharedMailboxCoordinates {
    /// Base URL of the Payjoin Directory.
    pub directory: Url,
    /// OHTTP key configuration for the directory.
    pub ohttp_keys: OhttpKeys,
    /// Shared HPKE keypair every session participant holds; used to seal writes
    /// and decrypt reads.
    pub shared_keypair: HpkeKeyPair,
    /// Short id addressing the session's shared mailbox.
    pub mailbox_id: ShortId,
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

impl Participant<HasPlan> {
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

    /// Coordinates a mailbox adapter needs to reach this session's shared mailbox.
    ///
    /// The state machine holds no transport and no crypto; it hands these session
    /// keys to the adapter, which owns OHTTP encapsulation and HPKE.
    pub fn shared_mailbox_coordinates(&self) -> SharedMailboxCoordinates {
        SharedMailboxCoordinates {
            directory: self.context.directory.clone(),
            ohttp_keys: self.context.ohttp_keys.clone(),
            shared_keypair: self.context.session_shared_keypair(),
            mailbox_id: self.context.session_shared_mailbox_id(),
        }
    }

    /// The plaintext PSBT fragment to post for the current plan action, or `None`
    /// once every action has been posted.
    pub fn next_action_fragment(&self) -> Option<Psbt> {
        self.state.plan.action(self.state.plan_cursor).map(|action| action.as_psbt_fragment())
    }

    /// Record that the current action's fragment was posted to the shared
    /// mailbox, advancing the plan.
    ///
    /// The mailbox adapter confirms the write, so this only advances the cursor
    /// and emits the [`MultipartySessionEvent::PlanExecuted`] event.
    pub fn record_action_posted(&self) -> PlanExecutionTransition {
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
    /// The mailbox adapter has already decrypted *and parsed* these fragments,
    /// and the network task forwards only the ones past the persisted count
    /// (which it learns from [`HasPlan::directory_psbt_fragment_count`]).
    /// So this simply appends one [`MultipartySessionEvent::PlanDirectoryPsbtFragment`]
    /// per fragment — no positional dedup of raw frames, which is what previously
    /// let an invalid frame cause a valid fragment to be re-recorded.
    pub fn record_fragments(&self, fragments: &[Psbt]) -> PlanReadTransition {
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
    use concurrent_psbt::constructor::Creator;

    use super::PlanPsbtAccumulator;
    use crate::multiparty::participant::plan::PlanBuilder;

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
}
