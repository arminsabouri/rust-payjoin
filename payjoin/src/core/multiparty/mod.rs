#[cfg(test)]
mod test_helpers;

pub mod initiator;
pub mod participant;
pub mod persist;
pub mod responder;
pub mod session;
pub mod session_creator;
#[cfg_attr(docsrs, doc(cfg(feature = "multiparty")))]
pub mod session_parameters;
#[cfg_attr(docsrs, doc(cfg(feature = "multiparty")))]
pub mod uri;
pub use initiator::{
    Initialized as InitiatorInitialized, Initiator, InitiatorBuilder, InitiatorContext,
    InitiatorError, InitiatorSessionError,
};
pub use participant::{
    parse_mailbox_psbt_fragment, AwaitingParticipantContext, HasPlan, HasSessionParameters,
    Participant, ParticipantAwaitingSessionParameters, ParticipantContext, ParticipantError,
    ParticipantSessionError, PlanExecuted, PlanExecution, PlanExecutionTransition,
    PlanPsbtAccumulator, PlanReadTransition, PsbtFragmentError, SharedMailboxCoordinates,
};
pub use persist::{
    EventfulTransition, GraduationError, InMemoryMultipartyRegistry,
    MultipartyGraduationTransition, MultipartySessionRegistry, ParticipantParametersAdoption,
    RegistryError, SessionParametersPollFailure, SessionParametersPollTransition,
};
/// The validated concurrent-PSBT fragment type exchanged over the shared mailbox.
pub use psbt_v2::v2::Psbt;
pub use responder::{
    Initialized as ResponderInitialized, Responder, ResponderBuilder, ResponderContext,
    ResponderError, ResponderSessionError,
};
pub use session::{
    collect_open_sessions_awaiting_parameters,
    collect_open_sessions_awaiting_parameters_with_persisters, replay_event_log,
    CollectAwaitingParametersError, MultipartySession, MultipartySessionEvent,
    MultipartySessionOutcome, SessionHistory, SessionStatus,
};
pub use session_creator::{
    CollectedSessions, ParametersDelivery, ParametersDistributionTransition, PendingParticipant,
    SessionCreator, SessionCreatorBuilder, SessionCreatorContext, SessionCreatorError,
    SessionCreatorPromoteError, SessionCreatorSessionError, SessionParametersDistributionMessage,
};
pub use session_parameters::{
    InputScriptType, SessionParameters, SessionParametersError, SESSION_SECRET_LEN,
};
pub use uri::{build_multiparty_pj_uri, MultipartyPjUri, MultipartyUriError};
