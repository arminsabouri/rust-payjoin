//! Driver for the multiparty bootstrap stages (before plan execution).
//!
//! Bootstrap runs before a shared session secret exists, so its messages can't
//! ride the shared plan mailbox; each is a message A over a per-participant
//! mailbox. A [`BootstrapMailbox`] owns all of that transport — OHTTP, HPKE
//! sealing/opening, and HTTP — so the state machines only hand it their exact
//! mailbox target and keys as a [`PollIo`]/[`PostIo`].
//!
//! Every bootstrap stage fits one of two rhythms, so there are two generic
//! drivers rather than one per stage:
//!
//! - [`drive_poll`] drives a [`PollStage`] (initiator, awaiting-participant): poll
//!   the mailbox until a message arrives, then advance.
//! - [`drive_post`] drives a [`PostStage`] (responder, session creator): post to
//!   each recipient in turn, advancing after each ack.
//!
//! [`drive_session`] dispatches on the replayed [`MultipartySession`] and runs a
//! single session log through its bootstrap stages until it reaches session
//! parameters (ready for plan generation, a caller concern), a plan, or a closed
//! outcome.

use payjoin::multiparty::{
    poll_request, post_request, process_poll_response, process_post_ack, replay_event_log,
    CollectedSessions, Initiator, InitiatorEvent, InitiatorInitialized, MultipartySession,
    MultipartySessionEvent, MultipartySessionRegistry, ParticipantAwaitingEvent,
    ParticipantAwaitingSessionParameters, PollIo, PostIo, Responder, ResponderEvent,
    ResponderInitialized, SessionCreator, SessionCreatorEvent,
};
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};
use payjoin::{HpkePublicKey, Request};

use crate::error::DriverError;

fn boot<E: std::error::Error + Send + Sync + 'static>(error: E) -> DriverError {
    DriverError::Bootstrap(Box::new(error))
}

fn persisted<E: std::fmt::Display>(error: E) -> DriverError {
    DriverError::Persist(error.to_string())
}

/// A message-generic mailbox that owns all bootstrap transport.
///
/// The state machine supplies the addressing and keys ([`PollIo`]/[`PostIo`]);
/// this adapter performs the OHTTP encapsulation, HPKE sealing/opening, and HTTP.
/// Like the plan driver's dependencies it carries no `Send` bound, so it runs on
/// single-threaded executors too.
#[allow(async_fn_in_trait)]
pub trait BootstrapMailbox {
    /// Transport/crypto failure from the underlying implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Poll `io`'s mailbox and open the first message A sealed to it, returning its
    /// `(payload, sender_reply_key)` or `None` if the directory has nothing yet.
    async fn poll(&self, io: &PollIo) -> Result<Option<(Vec<u8>, HpkePublicKey)>, Self::Error>;

    /// Seal `io`'s payload from its sender to its recipient, post it, and await the
    /// directory ack.
    async fn post(&self, io: &PostIo) -> Result<(), Self::Error>;
}

/// A bootstrap stage driven by polling one mailbox until a message arrives.
pub trait PollStage: Sized {
    /// The mailbox to poll and the key that opens its inbound message A.
    fn poll_io(&self) -> PollIo;

    /// Interpret the opened message, persist the resulting transition, and return
    /// the persister the session continues on (a new log after a graduation).
    fn advance<R>(
        self,
        payload: Vec<u8>,
        sender: HpkePublicKey,
        registry: &mut R,
        persister: &R::Persister,
    ) -> Result<R::Persister, DriverError>
    where
        R: MultipartySessionRegistry,
        R::Persister: Clone;
}

/// A bootstrap stage driven by posting to each recipient in turn.
pub trait PostStage: Sized {
    /// The next message to post, or `None` when every recipient has been served.
    fn next_post(&self) -> Result<Option<PostIo>, DriverError>;

    /// Persist the transition after the post to `recipient` is acked, returning the
    /// next stage to post from, or `None` once the stage is done.
    fn advance<P>(
        self,
        recipient: HpkePublicKey,
        persister: &P,
    ) -> Result<Option<Self>, DriverError>
    where
        P: SessionPersister<SessionEvent = MultipartySessionEvent>;
}

/// Poll `stage`'s mailbox until a message arrives, then advance it.
pub async fn drive_poll<S, M, R>(
    mailbox: &M,
    stage: S,
    registry: &mut R,
    persister: &R::Persister,
) -> Result<R::Persister, DriverError>
where
    S: PollStage,
    M: BootstrapMailbox,
    R: MultipartySessionRegistry,
    R::Persister: Clone,
{
    let io = stage.poll_io();
    loop {
        if let Some((payload, sender)) = mailbox.poll(&io).await.map_err(boot)? {
            return stage.advance(payload, sender, registry, persister);
        }
        // Nothing yet (HTTP 202); the directory long-polls, so retry immediately.
    }
}

/// Post `stage`'s messages to each recipient in turn until it is done.
pub async fn drive_post<S, M, P>(mailbox: &M, stage: S, persister: &P) -> Result<(), DriverError>
where
    S: PostStage,
    M: BootstrapMailbox,
    P: SessionPersister<SessionEvent = MultipartySessionEvent>,
{
    let mut stage = stage;
    while let Some(io) = stage.next_post()? {
        mailbox.post(&io).await.map_err(boot)?;
        match stage.advance(io.recipient, persister)? {
            Some(next) => stage = next,
            None => return Ok(()),
        }
    }
    Ok(())
}

impl PollStage for Initiator<InitiatorInitialized> {
    fn poll_io(&self) -> PollIo { self.poll_io() }

    fn advance<R>(
        self,
        _payload: Vec<u8>,
        sender: HpkePublicKey,
        _registry: &mut R,
        persister: &R::Persister,
    ) -> Result<R::Persister, DriverError>
    where
        R: MultipartySessionRegistry,
        R::Persister: Clone,
    {
        self.step(InitiatorEvent::ReplyKeyRead(sender)).save(persister).map_err(persisted)?;
        Ok(persister.clone())
    }
}

impl PollStage for ParticipantAwaitingSessionParameters {
    fn poll_io(&self) -> PollIo { self.poll_io() }

    fn advance<R>(
        self,
        payload: Vec<u8>,
        _sender: HpkePublicKey,
        registry: &mut R,
        persister: &R::Persister,
    ) -> Result<R::Persister, DriverError>
    where
        R: MultipartySessionRegistry,
        R::Persister: Clone,
    {
        let params = self.parse_parameters(&payload).map_err(boot)?;
        match self
            .step(ParticipantAwaitingEvent::ParametersRead(params))
            .save(registry, persister)
            .map_err(persisted)?
        {
            OptionalTransitionOutcome::Progress(adopted) => Ok(adopted),
            // `step` always adopts on a read, so Stasis is unreachable here.
            OptionalTransitionOutcome::Stasis(_) => Err(DriverError::UnexpectedState),
        }
    }
}

impl PostStage for Responder<ResponderInitialized> {
    fn next_post(&self) -> Result<Option<PostIo>, DriverError> {
        Ok(Some(self.post_io().map_err(boot)?))
    }

    fn advance<P>(
        self,
        _recipient: HpkePublicKey,
        persister: &P,
    ) -> Result<Option<Self>, DriverError>
    where
        P: SessionPersister<SessionEvent = MultipartySessionEvent>,
    {
        self.step(ResponderEvent::ReplyKeyPosted).save(persister).map_err(persisted)?;
        Ok(None)
    }
}

impl PostStage for SessionCreator<CollectedSessions> {
    fn next_post(&self) -> Result<Option<PostIo>, DriverError> { Ok(self.post_io()) }

    fn advance<P>(
        self,
        recipient: HpkePublicKey,
        persister: &P,
    ) -> Result<Option<Self>, DriverError>
    where
        P: SessionPersister<SessionEvent = MultipartySessionEvent>,
    {
        match self
            .step(SessionCreatorEvent::ParametersDeliveredTo(recipient))
            .save(persister)
            .map_err(persisted)?
        {
            MultipartySession::SessionCreatorCollectedSessions(next) => Ok(Some(next)),
            MultipartySession::ParticipantHasSessionParameters(_) => Ok(None),
            _ => Err(DriverError::UnexpectedState),
        }
    }
}

/// Drive one session log through its bootstrap stages.
///
/// Advances the session in `persister` — posting or polling as its current stage
/// requires — until it reaches a state past bootstrap: session parameters adopted
/// (ready for plan generation, a caller concern), a plan, or a closed outcome.
/// Returns the persister the session now lives on (a *new* log after the
/// awaiting-parameters graduation, otherwise the one passed in).
pub async fn drive_session<M, R>(
    mailbox: &M,
    registry: &mut R,
    persister: R::Persister,
) -> Result<R::Persister, DriverError>
where
    M: BootstrapMailbox,
    R: MultipartySessionRegistry,
    R::Persister: Clone,
{
    let mut current = persister;
    loop {
        let (session, _) = replay_event_log(&current)?;
        match session {
            MultipartySession::ResponderInitialized(responder) =>
                drive_post(mailbox, responder, &current).await?,
            MultipartySession::InitiatorInitialized(initiator) =>
                current = drive_poll(mailbox, initiator, registry, &current).await?,
            MultipartySession::SessionCreatorCollectedSessions(creator) =>
                drive_post(mailbox, creator, &current).await?,
            MultipartySession::ParticipantAwaitingSessionParameters(participant) =>
                current = drive_poll(mailbox, participant, registry, &current).await?,
            // Past bootstrap: hand back to the caller (plan generation and
            // execution are separate concerns).
            MultipartySession::ParticipantHasSessionParameters(_)
            | MultipartySession::ParticipantHasPlan(_)
            | MultipartySession::Closed(_) => return Ok(current),
        }
    }
}

/// A [`reqwest`]-backed [`BootstrapMailbox`] over a Payjoin Directory.
#[cfg(feature = "reqwest")]
#[derive(Clone)]
pub struct DirectoryBootstrapMailbox {
    client: reqwest::Client,
    ohttp_relay: payjoin::Url,
}

#[cfg(feature = "reqwest")]
impl DirectoryBootstrapMailbox {
    /// Build a mailbox from a `reqwest` client and an OHTTP relay.
    pub fn new(client: reqwest::Client, ohttp_relay: payjoin::Url) -> Self {
        Self { client, ohttp_relay }
    }

    async fn send(&self, request: Request) -> Result<Vec<u8>, reqwest::Error> {
        let response = self
            .client
            .post(request.url)
            .header("Content-Type", request.content_type)
            .body(request.body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.bytes().await?.to_vec())
    }
}

/// Transport failure from [`DirectoryBootstrapMailbox`].
#[cfg(feature = "reqwest")]
#[derive(Debug)]
pub enum DirectoryBootstrapError {
    /// OHTTP encapsulation, HPKE, or directory-response decoding failed.
    Mailbox(payjoin::multiparty::MailboxError),
    /// The HTTP request itself failed.
    Http(reqwest::Error),
}

#[cfg(feature = "reqwest")]
impl std::fmt::Display for DirectoryBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mailbox(e) => write!(f, "bootstrap mailbox error: {e}"),
            Self::Http(e) => write!(f, "HTTP error: {e}"),
        }
    }
}

#[cfg(feature = "reqwest")]
impl std::error::Error for DirectoryBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mailbox(e) => Some(e),
            Self::Http(e) => Some(e),
        }
    }
}

#[cfg(feature = "reqwest")]
impl From<payjoin::multiparty::MailboxError> for DirectoryBootstrapError {
    fn from(e: payjoin::multiparty::MailboxError) -> Self { Self::Mailbox(e) }
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for DirectoryBootstrapError {
    fn from(e: reqwest::Error) -> Self { Self::Http(e) }
}

#[cfg(feature = "reqwest")]
impl BootstrapMailbox for DirectoryBootstrapMailbox {
    type Error = DirectoryBootstrapError;

    async fn poll(&self, io: &PollIo) -> Result<Option<(Vec<u8>, HpkePublicKey)>, Self::Error> {
        let (request, ctx) = poll_request(io, self.ohttp_relay.as_str())?;
        let body = self.send(request).await?;
        Ok(process_poll_response(&body, ctx, &io.decrypt_key)?)
    }

    async fn post(&self, io: &PostIo) -> Result<(), Self::Error> {
        let (request, ctx) = post_request(io, self.ohttp_relay.as_str())?;
        let body = self.send(request).await?;
        process_post_ack(&body, ctx)?;
        Ok(())
    }
}
