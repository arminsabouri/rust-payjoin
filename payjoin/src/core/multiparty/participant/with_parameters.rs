use psbt_v2::v2::Psbt;
use serde::{Deserialize, Serialize};

use super::plan::{parse_mailbox_psbt_fragment, PlanBuilder};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasSessionParameters {}

impl Participant<HasSessionParameters> {
    pub(crate) fn from_adopted_context(context: ParticipantContext) -> Self {
        Self { state: HasSessionParameters {}, context }
    }

    pub fn session_parameters(&self) -> &SessionParameters { &self.context.session_parameters }

    pub(crate) fn apply_with_plan(self, plan: Plan) -> MultipartySession {
        MultipartySession::ParticipantHasPlan(Participant {
            state: HasPlan { plan, plan_cursor: 0, directory_read_cursor: 0 },
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
                state: HasPlan { plan, plan_cursor: 0, directory_read_cursor: 0 },
                context: self.context.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasPlan {
    pub(crate) plan: Plan,
    pub(crate) plan_cursor: usize,
    /// Number of frames already consumed from the append-only shared mailbox.
    ///
    /// The mailbox is read in full on every round, so this marks how far we have
    /// already processed and lets us skip re-reading frames we have seen. It is
    /// derived from the log: [`Self::apply_directory_psbt_fragment`] advances it by one
    /// per persisted [`MultipartySessionEvent::PlanDirectoryPsbtFragment`]. Invalid
    /// mailbox frames are skipped without an event and advance this cursor only at runtime.
    pub(crate) directory_read_cursor: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyToExecutePlan {
    pub(crate) plan: Plan,
    pub(crate) plan_cursor: usize,
    pub(crate) directory_read_cursor: usize,
    /// Validated PSBT fragments newly read this round (those past `directory_read_cursor`).
    pub(crate) directory_psbt_fragments: Vec<Psbt>,
}

impl Participant<HasPlan> {
    pub(crate) fn apply_directory_psbt_fragment(
        mut self,
        _directory_psbt_fragment: Psbt,
    ) -> MultipartySession {
        self.state.directory_read_cursor += 1;
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

    /// Create an OHTTP encapsulated request to read the shared session mailbox before executing the
    /// next plan action.
    pub fn create_read_from_directory_request(
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

    /// Process and persist validated PSBT fragments that may affect plan re-evaluation.
    ///
    /// The shared mailbox is append-only and returned in full, so frames before
    /// [`HasPlan::directory_read_cursor`] have already been processed on an
    /// earlier round and are skipped. Newly appended frames that parse as valid
    /// PSBT fragments become [`MultipartySessionEvent::PlanDirectoryPsbtFragment`]
    /// events; invalid frames are skipped without closing the session.
    pub fn process_read_from_directory_response(
        &self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> PlanReadTransition {
        let all_messages =
            match process_read_response(body, context, &self.context.session_shared_keypair()) {
                Ok(messages) => messages,
                Err(e) => {
                    let err = ParticipantError::from(e);
                    if matches!(&err, ParticipantError::DirectoryResponse(e) if !e.is_fatal()) {
                        return PlanReadTransition::transient(err);
                    }
                    return PlanReadTransition::fatal(
                        MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                        err,
                    );
                }
            };

        let already_read = self.state.directory_read_cursor;
        let mut new_fragments = Vec::new();
        let mut events = Vec::new();
        let mut new_frame_count = 0;

        for message in all_messages.into_iter().skip(already_read) {
            new_frame_count += 1;
            let Ok(fragment) = parse_mailbox_psbt_fragment(&message) else {
                continue;
            };
            events.push(MultipartySessionEvent::PlanDirectoryPsbtFragment(fragment.clone()));
            new_fragments.push(fragment);
        }

        let ready = Participant {
            state: ReadyToExecutePlan {
                plan: self.state.plan.clone(),
                plan_cursor: self.state.plan_cursor,
                directory_read_cursor: already_read + new_frame_count,
                directory_psbt_fragments: new_fragments,
            },
            context: self.context.clone(),
        };

        PlanReadTransition::success(events, ready)
    }
}

impl Participant<ReadyToExecutePlan> {
    pub fn directory_psbt_fragments(&self) -> &[Psbt] { &self.state.directory_psbt_fragments }

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
            PlanExecution::NeedsDirectoryRead(Participant {
                state: HasPlan {
                    plan,
                    plan_cursor,
                    directory_read_cursor: self.state.directory_read_cursor,
                },
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
    EventfulTransition<MultipartySessionEvent, Participant<ReadyToExecutePlan>, ParticipantError>;

// TODO: evaluate if we want stronger state transition types than just PlanExecution. In the current use case we just have two states: current and next
// And rn I cant think of any other states we would end up in from process a post res
pub type PlanExecutionTransition =
    EventfulTransition<MultipartySessionEvent, PlanExecution, ParticipantError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExecuted {}
