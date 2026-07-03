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
            state: HasPlan { plan, plan_cursor: 0 },
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
            Participant { state: HasPlan { plan, plan_cursor: 0 }, context: self.context.clone() },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasPlan {
    pub(crate) plan: Plan,
    pub(crate) plan_cursor: usize,
}

impl Participant<HasPlan> {
    pub(crate) fn apply_directory_psbt_fragment(
        self,
        _directory_psbt_fragment: Psbt,
    ) -> MultipartySession {
        // The fragment lives in the event log; its running count is derived from
        // the log via `SessionHistory::directory_psbt_fragment_count`, so the
        // state itself carries no read cursor.
        MultipartySession::ParticipantHasPlan(self)
    }

    pub(crate) fn apply_with_plan_cursor(mut self, plan_cursor: usize) -> MultipartySession {
        if plan_cursor >= self.state.plan.len() {
            return MultipartySession::ParticipantPlanExecuted(Participant {
                state: PlanExecuted {},
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
    ///
    /// Pure plan logic — no crypto. The adapter seals and posts the returned
    /// fragment.
    pub fn next_action_fragment(&self) -> Option<Psbt> {
        self.state.plan.action(self.state.plan_cursor).map(|action| action.as_psbt_fragment())
    }

    /// Record that the current action's fragment was posted to the shared
    /// mailbox, advancing the plan.
    ///
    /// The mailbox adapter confirms the write, so this only advances the cursor
    /// and emits the [`MultipartySessionEvent::PlanExecuted`] event.
    pub fn record_action_posted(&self) -> PlanExecutionTransition {
        let plan = self.state.plan.clone();
        let plan_cursor = self.state.plan_cursor + 1;

        let execution = if plan_cursor >= plan.len() {
            PlanExecution::Executed(Participant {
                state: PlanExecuted {},
                context: self.context.clone(),
            })
        } else {
            PlanExecution::NeedsDirectoryRead(Participant {
                state: HasPlan { plan, plan_cursor },
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
    /// (which it learns from [`crate::multiparty::SessionHistory::directory_psbt_fragment_count`]).
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
pub struct PlanExecuted {}
