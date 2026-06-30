use serde::{Deserialize, Serialize};

use super::plan::PlanBuilder;
use super::{ParticipantError, Plan};
use crate::append_mailbox::{append_request, process_read_response, read_request, MailboxError};
use crate::hpke::HpkeKeyPair;
use crate::multiparty::persist::EventfulTransition;
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::session_parameters::SessionParameters;
use crate::ohttp::process_post_res;
use crate::persist::NextStateTransition;
use crate::receive::InputPair;
use crate::uri::ShortId;
use crate::{IntoUrl, OhttpKeys, Request, Url};

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

/// Multiparty participant state machine (post role bootstrap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant<State> {
    pub(crate) state: State,
    pub(crate) context: ParticipantContext,
}

impl<State> Participant<State> {
    fn create_read_from_directory_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), MailboxError> {
        read_request(
            &self.context.ohttp_keys,
            &self.context.directory,
            ohttp_relay,
            &self.context.session_shared_mailbox_id(),
        )
    }

    fn process_read_from_directory_response(
        &self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Vec<Vec<u8>>, MailboxError> {
        process_read_response(body, context, &self.context.session_shared_keypair())
    }
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

// Once you have a plan, we should read over the available actions and execute them.
// we will also need to read existing messages from the directory and persist them
// For now lets just execute the actions and then read other's. once we read a others
// messages we will need to re-evaluate the plan and update our cursor. And potentially decide a better
// branch in the plan
impl Participant<HasPlan> {
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

    pub fn execute_action_from_plan(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), MailboxError> {
        let action =
            self.state.plan.action(self.state.plan_cursor).expect("plan cursor is out of bounds");
        let msg = action.as_psbt_fragment().serialize();
        let session_shared_keypair = self.context.session_shared_keypair();
        append_request(
            &self.context.ohttp_keys,
            &self.context.directory,
            ohttp_relay,
            &msg,
            session_shared_keypair.public_key(),
        )
    }

    pub fn process_action_response(
        &self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> PlanExecutionTransition {
        let plan = self.state.plan.clone();
        let plan_cursor = self.state.plan_cursor + 1;

        if let Err(e) = process_post_res(body, context) {
            let is_fatal = e.is_fatal();
            let err = ParticipantError::DirectoryResponse(e);
            if !is_fatal {
                return PlanExecutionTransition::transient(err);
            }
            return PlanExecutionTransition::fatal(
                MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                err,
            );
        }

        let execution = if plan_cursor >= plan.len() {
            PlanExecution::Executed(Participant {
                state: PlanExecuted {},
                context: self.context.clone(),
            })
        } else {
            PlanExecution::Executing(Participant {
                state: HasPlan { plan, plan_cursor },
                context: self.context.clone(),
            })
        };

        PlanExecutionTransition::success(
            [MultipartySessionEvent::PlanExecuted(plan_cursor)],
            execution,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExecution {
    Executing(Participant<HasPlan>),
    Executed(Participant<PlanExecuted>),
}

impl From<PlanExecution> for MultipartySession {
    fn from(execution: PlanExecution) -> Self {
        match execution {
            PlanExecution::Executing(state) => MultipartySession::ParticipantHasPlan(state),
            PlanExecution::Executed(state) => MultipartySession::ParticipantPlanExecuted(state),
        }
    }
}

// TODO: evaluate if we want stronger state transition types than just PlanExecution. In the current use case we just have two states: current and next
// And rn I cant think of any other states we would end up in from process a post res
pub type PlanExecutionTransition =
    EventfulTransition<MultipartySessionEvent, PlanExecution, ParticipantError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExecuted {}
