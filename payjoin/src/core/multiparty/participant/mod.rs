mod error;
mod plan;

use bitcoin::hashes::{sha256, Hash};
pub use error::{ParticipantError, ParticipantSessionError};
pub use plan::Plan;
use serde::{Deserialize, Serialize};

use crate::append_mailbox::{append_request, MailboxError};
use crate::hpke::{decrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::multiparty::participant::plan::PlanBuilder;
use crate::multiparty::persist::{
    ParticipantParametersAdoption, SessionParametersPollFailure, SessionParametersPollTransition,
};
use crate::multiparty::session::{
    MultipartySession, MultipartySessionEvent, MultipartySessionOutcome,
};
use crate::multiparty::session_parameters::SessionParameters;
use crate::ohttp::{ohttp_encapsulate, process_get_res, process_post_res};
use crate::persist::{MaybeFatalTransitionWithNoResults, NextStateTransition};
use crate::receive::v2::mailbox_endpoint;
use crate::receive::InputPair;
use crate::uri::ShortId;
use crate::{IntoUrl, OhttpKeys, Request, Url};

/// Persistent context for a multiparty participant awaiting or holding session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantContext {
    mailbox_key: HpkeKeyPair,
    pub(crate) directory: Url,
    pub ohttp_keys: OhttpKeys,
    pub(crate) session_parameters: Option<SessionParameters>,
    /// The other party's HPKE public key (initiator for responders, responder for initiators).
    pub(crate) reply_key: HpkePublicKey,
}

impl ParticipantContext {
    pub(crate) fn new(
        mailbox_key: HpkeKeyPair,
        directory: Url,
        ohttp_keys: OhttpKeys,
        reply_key: HpkePublicKey,
    ) -> Self {
        Self {
            mailbox_key,
            directory: directory.payjoin_directory_origin(),
            ohttp_keys,
            session_parameters: None,
            reply_key,
        }
    }
}

/// Multiparty participant state machine (post role bootstrap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant<State> {
    pub(crate) state: State,
    pub(crate) context: ParticipantContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitingSessionParameters {
    /// HPKE public key for the Payjoin Directory mailbox that receives session parameters.
    pub(crate) parameters_mailbox_public_key: HpkePublicKey,
}

impl Participant<AwaitingSessionParameters> {
    /// Mailbox where the session creator POSTs parameters and this participant polls.
    pub(crate) fn parameters_mailbox_public_key(&self) -> &HpkePublicKey {
        &self.state.parameters_mailbox_public_key
    }

    fn parameters_mailbox_short_id(&self) -> ShortId {
        sha256::Hash::hash(&self.state.parameters_mailbox_public_key.to_compressed_bytes()).into()
    }

    fn session_parameters_poll_body(
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        ParticipantError,
    > {
        let poll_target =
            mailbox_endpoint(&self.context.directory, &self.parameters_mailbox_short_id());
        ohttp_encapsulate(&self.context.ohttp_keys, "GET", poll_target.as_str(), None)
            .map_err(ParticipantError::OhttpEncapsulation)
    }

    /// Create an OHTTP encapsulated HTTP GET request to poll this participant's mailbox for
    /// HPKE-encrypted session parameters from the session creator.
    pub fn create_session_parameters_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), ParticipantError> {
        let (body, ohttp_ctx) = self.session_parameters_poll_body()?;
        let relay_url = crate::ohttp::full_relay_url(ohttp_relay, &self.context.directory)?;
        let req = Request::new_v2(&relay_url, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process the directory response after polling for session parameters.
    ///
    /// Returns no-results when the directory has nothing yet (HTTP 202 ACCEPTED).
    pub fn process_session_parameters_poll_response(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<SessionParametersPollTransition, SessionParametersPollFailure> {
        let current_state = self.clone();
        let session_parameters = match self.inner_process_session_parameters_poll_res(body, context)
        {
            Ok(session_parameters) => session_parameters,
            Err(e) => match &e {
                ParticipantError::DirectoryResponse(directory_error)
                    if !directory_error.is_fatal() =>
                {
                    return Err(SessionParametersPollFailure::Transient(e));
                }
                _ =>
                    return Err(SessionParametersPollFailure::Fatal(
                        MaybeFatalTransitionWithNoResults::fatal(
                            MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure),
                            e,
                        ),
                    )),
            },
        };

        if let Some(session_parameters) = session_parameters {
            Ok(SessionParametersPollTransition::Adoption(
                ParticipantParametersAdoption::from_awaiting_participant(
                    &current_state,
                    session_parameters,
                ),
            ))
        } else {
            Ok(SessionParametersPollTransition::Stasis(current_state))
        }
    }

    fn inner_process_session_parameters_poll_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<SessionParameters>, ParticipantError> {
        let body =
            match process_get_res(body, context).map_err(ParticipantError::DirectoryResponse)? {
                Some(body) => body,
                None => return Ok(None),
            };

        let (params_bytes, _creator_pubkey) =
            decrypt_message_a(&body, self.context.mailbox_key.secret_key())
                .map_err(ParticipantError::Hpke)?;
        let session_parameters = SessionParameters::from_message_a_body(&params_bytes)
            .map_err(ParticipantError::SessionParameters)?;
        Ok(Some(session_parameters))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HasSessionParameters {}

impl Participant<HasSessionParameters> {
    pub(crate) fn from_adopted_context(context: ParticipantContext) -> Self {
        debug_assert!(
            context.session_parameters.is_some(),
            "adopted participant context must include session parameters"
        );
        Self { state: HasSessionParameters {}, context }
    }

    pub fn session_parameters(&self) -> &SessionParameters {
        self.context
            .session_parameters
            .as_ref()
            .expect("HasSessionParameters state must have session_parameters in context")
    }

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

    pub(crate) fn generate_plan(
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
        append_request(
            &self.context.ohttp_keys,
            &self.context.directory,
            ohttp_relay,
            &msg,
            &self.context.reply_key,
        )
    }

    pub fn process_action_response(
        &self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        MultipartySessionEvent,
        Participant<PlanExecuted>,
        Participant<HasPlan>,
        ParticipantError,
    > {
        let plan = self.state.plan.clone();
        let plan_cursor = self.state.plan_cursor + 1;

        process_post_res(body, context).expect("remove this later TODO");
        if plan_cursor >= plan.len() {
            return MaybeFatalTransitionWithNoResults::success(
                MultipartySessionEvent::PlanExecuted(plan_cursor),
                Participant { state: PlanExecuted {}, context: self.context.clone() },
            );
        } 
        MaybeFatalTransitionWithNoResults::no_results(
            MultipartySessionEvent::PlanExecuted(plan_cursor),
            Participant { state: HasPlan { plan, plan_cursor }, context: self.context.clone() },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExecuted {}
