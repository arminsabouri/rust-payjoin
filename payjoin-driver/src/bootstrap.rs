//! Bootstrap driver: push a session from the reply-key handshake to a plan.
//!
//! The [`Initiator`]/[`Responder`] reply-key handshake stays manual. Once a
//! session reaches [`ParticipantAwaitingSessionParameters`] — or a caller has
//! promoted collected awaiting sessions into a [`SessionCreator`] via
//! [`SessionCreatorBuilder::build_and_promote`] — this driver takes over and runs
//! the sequential poll/distribute/plan loop until the log reaches
//! [`HasPlan`](payjoin::multiparty::HasPlan). The caller then builds the shared
//! mailbox and hands off to [`execute_plan`](crate::participant::execute_plan).
//!
//! Unlike the plan driver, the bootstrap typestates still own their OHTTP/HPKE:
//! they build a fully-encapsulated [`Request`](payjoin::Request) and decrypt the
//! response themselves. This driver only owns the loop and the HTTP round-trip
//! (via [`RequestSender`]) — control inversion first, I/O purity later.
//!
//! [`Initiator`]: payjoin::multiparty::Initiator
//! [`Responder`]: payjoin::multiparty::Responder
//! [`ParticipantAwaitingSessionParameters`]: payjoin::multiparty::ParticipantAwaitingSessionParameters
//! [`SessionCreator`]: payjoin::multiparty::SessionCreator
//! [`SessionCreatorBuilder::build_and_promote`]: payjoin::multiparty::SessionCreatorBuilder::build_and_promote

use std::error::Error as StdError;
use std::fmt;

use payjoin::multiparty::{
    replay_event_log, MultipartySession, MultipartySessionEvent, MultipartySessionRegistry,
    SessionParametersPollFailure,
};
use payjoin::persist::{OptionalTransitionOutcome, SessionPersister};

use crate::error::DriverError;
use crate::request_sender::RequestSender;
use crate::signer::Signer;

/// Drive one open session from bootstrap up to (but not through) its plan.
///
/// Returns the open persister for the log, now replaying to
/// [`ParticipantHasPlan`](payjoin::multiparty::MultipartySession::ParticipantHasPlan)
/// (or already `Closed`). The registry is written only by the awaiting-parameters
/// adoption, which graduates that log to a fresh `HasSessionParameters` log; every
/// other stage stays on the same persister.
///
/// The caller is responsible for the reply-key handshake before this, for
/// promoting awaiting sessions into a session creator (which needs the agreed
/// [`SessionParameters`](payjoin::multiparty::SessionParameters)), and for running
/// [`execute_plan`](crate::participant::execute_plan) after.
pub async fn drive_to_plan<R, T, W>(
    registry: &mut R,
    mut persister: R::Persister,
    sender: &T,
    wallet: &W,
    ohttp_relay: payjoin::Url,
) -> Result<R::Persister, DriverError>
where
    R: MultipartySessionRegistry,
    R::Persister: SessionPersister<SessionEvent = MultipartySessionEvent> + Clone,
    T: RequestSender,
    W: Signer,
{
    loop {
        let (session, _) = replay_event_log(&persister)?;
        match session {
            // Poll this participant's mailbox for the creator's session parameters.
            MultipartySession::ParticipantAwaitingSessionParameters(awaiting) => {
                let (request, ctx) = awaiting
                    .create_session_parameters_poll_request(ohttp_relay.as_str())
                    .map_err(bootstrap)?;
                let body = sender.send(request).await.map_err(mailbox)?;
                match awaiting.process_session_parameters_poll_response(&body, ctx) {
                    Ok(transition) =>
                        match transition.save(registry, &persister).map_err(persisted)? {
                            // Adopted: continue on the freshly graduated log.
                            OptionalTransitionOutcome::Progress(adopted) => persister = adopted,
                            // Nothing yet; re-poll.
                            OptionalTransitionOutcome::Stasis(_) => {}
                        },
                    // Transient directory error; re-poll.
                    Err(SessionParametersPollFailure::Transient(_)) => {}
                    // Fatal: `save` records the close and returns the fatal error.
                    Err(SessionParametersPollFailure::Fatal(fatal)) => {
                        fatal.save(&persister).map_err(persisted)?;
                        // TODO: do not loop again on fatal error
                    }
                }
            }
            // Distribute parameters to the next undelivered participant.
            MultipartySession::SessionCreatorCollectedSessions(creator) => {
                match creator
                    .next_session_parameters_distribution_message(ohttp_relay.as_str())
                    .map_err(bootstrap)?
                {
                    Some((message, request, ctx)) => {
                        let body = sender.send(request).await.map_err(mailbox)?;
                        creator
                            .process_session_parameters_distribution_response(
                                message.recipient,
                                &body,
                                ctx,
                            )
                            .save(&persister)
                            .map_err(persisted)?;
                    }
                    // Every participant is delivered only once the state has already
                    // transitioned to `HasSessionParameters`, so reaching this arm is
                    // a bug.
                    None => return Err(DriverError::UnexpectedState),
                }
            }
            // The wallet builds the plan outside the machine; hand it straight in.
            MultipartySession::ParticipantHasSessionParameters(has_params) => {
                let plan = wallet.plan().await.map_err(|e| DriverError::Sign(Box::new(e)))?;
                has_params.provide_plan(plan).save(&persister).map_err(persisted)?;
            }
            // Bootstrap complete (or the session already closed); hand off.
            MultipartySession::ParticipantHasPlan(_) | MultipartySession::Closed(_) =>
                return Ok(persister),
            // The reply-key handshake is the caller's job, not this driver's.
            MultipartySession::InitiatorInitialized(_)
            | MultipartySession::ResponderInitialized(_) =>
                return Err(DriverError::UnexpectedState),
        }
    }
}

fn mailbox<E: StdError + Send + Sync + 'static>(e: E) -> DriverError {
    DriverError::Mailbox(Box::new(e))
}

fn bootstrap<E: StdError + Send + Sync + 'static>(e: E) -> DriverError {
    DriverError::Bootstrap(Box::new(e))
}

fn persisted<E: fmt::Display>(e: E) -> DriverError { DriverError::Persist(e.to_string()) }
