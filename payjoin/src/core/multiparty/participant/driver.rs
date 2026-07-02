use std::{error, fmt};

use crate::append_mailbox::MailboxError;
use crate::error::ReplayError;
use crate::multiparty::participant::{ParticipantError, PlanExecution};
use crate::multiparty::session::{replay_event_log, MultipartySession, MultipartySessionEvent};
use crate::persist::{PersistedError, SessionPersister};
use crate::{IntoUrl, Request};

/// Sends OHTTP requests produced by the participant driver.
#[allow(async_fn_in_trait)]
pub trait ParticipantRequestSender {
    type Error: error::Error + Send + Sync + 'static;

    async fn send_request(&self, request: Request) -> Result<Vec<u8>, Self::Error>;
}

/// App-driven reactor for a participant with a fixed plan.
pub struct ParticipantDriver<'a, P, S, R> {
    persister: &'a P,
    sender: &'a S,
    ohttp_relay: R,
}

impl<'a, P, S, R> ParticipantDriver<'a, P, S, R> {
    pub fn new(persister: &'a P, sender: &'a S, ohttp_relay: R) -> Self {
        Self { persister, sender, ohttp_relay }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    Idle,
    InboxProgress { messages: usize },
    ActionAppended { plan_cursor: usize, plan_complete: bool },
    Complete,
}

#[derive(Debug)]
pub enum ParticipantDriverError<StorageError, SenderError>
where
    StorageError: error::Error + Send + Sync + 'static,
    SenderError: error::Error + Send + Sync + 'static,
{
    Replay(ReplayError<MultipartySession, MultipartySessionEvent>),
    Mailbox(MailboxError),
    Send(SenderError),
    Persist(PersistedError<ParticipantError, StorageError>),
}

impl<StorageError, SenderError> fmt::Display for ParticipantDriverError<StorageError, SenderError>
where
    StorageError: error::Error + Send + Sync + 'static,
    SenderError: error::Error + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(err) => write!(f, "replay event log: {err}"),
            Self::Mailbox(err) => write!(f, "mailbox request: {err}"),
            Self::Send(err) => write!(f, "send request: {err}"),
            Self::Persist(err) => write!(f, "persist transition: {err}"),
        }
    }
}

impl<StorageError, SenderError> error::Error for ParticipantDriverError<StorageError, SenderError>
where
    StorageError: error::Error + Send + Sync + 'static,
    SenderError: error::Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Replay(err) => Some(err),
            Self::Mailbox(err) => Some(err),
            Self::Send(err) => Some(err),
            Self::Persist(err) => Some(err),
        }
    }
}

impl<'a, P, S, R> ParticipantDriver<'a, P, S, R>
where
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
    S: ParticipantRequestSender,
    R: IntoUrl + Clone,
{
    pub async fn tick(
        &self,
    ) -> Result<TickOutcome, ParticipantDriverError<P::InternalStorageError, S::Error>> {
        let (session, _) =
            replay_event_log(self.persister).map_err(ParticipantDriverError::Replay)?;

        let participant = match session {
            MultipartySession::ParticipantHasPlan(participant) => participant,
            MultipartySession::ParticipantPlanExecuted(_) => return Ok(TickOutcome::Complete),
            _ => return Ok(TickOutcome::Idle),
        };

        let (read_request, read_context) = participant
            .create_read_from_directory_request(self.ohttp_relay.clone())
            .map_err(ParticipantDriverError::Mailbox)?;
        let read_body =
            self.sender.send_request(read_request).await.map_err(ParticipantDriverError::Send)?;
        let ready = participant
            .process_read_from_directory_response(&read_body, read_context)
            .save(self.persister)
            .map_err(ParticipantDriverError::Persist)?;

        let messages = ready.directory_messages().len();
        if messages > 0 {
            return Ok(TickOutcome::InboxProgress { messages });
        }

        let plan_cursor = ready.state.plan_cursor + 1;
        let (action_request, action_context) = ready
            .execute_action_from_plan(self.ohttp_relay.clone())
            .map_err(ParticipantDriverError::Mailbox)?;
        let action_body =
            self.sender.send_request(action_request).await.map_err(ParticipantDriverError::Send)?;
        let execution = ready
            .process_action_response(&action_body, action_context)
            .save(self.persister)
            .map_err(ParticipantDriverError::Persist)?;
        let plan_complete = matches!(execution, PlanExecution::Executed(_));

        Ok(TickOutcome::ActionAppended { plan_cursor, plan_complete })
    }
}
