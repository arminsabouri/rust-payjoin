//! Driver-level tests that exercise the participant plan driver over a mock,
//! non-reqwest [`SharedMailbox`] — proving the loop is composable with a swapped
//! mailbox and the existing [`InMemoryPersister`]. The happy path (which needs
//! valid OHTTP/HPKE traffic) is covered end-to-end in the `payjoin` crate's
//! integration test against real test services.

use std::cell::Cell;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use payjoin::multiparty::{MultipartySessionEvent, MultipartySessionOutcome, Plan, Psbt};
use payjoin::persist::{InMemoryPersister, SessionPersister};
use payjoin_driver::participant::execute_plan;
use payjoin_driver::{CollaborativeMessageSet, DriverError, Schedule, Signer};

/// A mailbox that records how many times it was read/written. The driver should
/// not reach it for sessions it can decide on from persisted state alone.
#[derive(Default)]
struct CountingMailbox {
    reads: Cell<usize>,
    writes: Cell<usize>,
}

struct EmptyMailboxMessages;

impl Stream for EmptyMailboxMessages {
    type Item = Result<Vec<Psbt>, NeverError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

#[derive(Debug)]
struct NeverError;
impl std::fmt::Display for NeverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("mailbox should not have been used")
    }
}
impl std::error::Error for NeverError {}

impl CollaborativeMessageSet for CountingMailbox {
    type Message = Psbt;
    type Error = NeverError;
    type Messages<'a> = EmptyMailboxMessages;

    async fn write(&self, _message: Psbt) -> Result<(), Self::Error> {
        self.writes.set(self.writes.get() + 1);
        Err(NeverError)
    }

    fn read(&self) -> Self::Messages<'_> {
        self.reads.set(self.reads.get() + 1);
        EmptyMailboxMessages
    }
}

/// A schedule that never yields. These tests reject the session from persisted
/// state before any action could become due, so the schedule is never polled.
struct PendingSchedule;

struct PendingDueActions;

impl Stream for PendingDueActions {
    type Item = Result<usize, NeverError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Schedule for PendingSchedule {
    type Error = NeverError;
    type DueActions<'a> = PendingDueActions;

    fn due_actions(&self, _plan: &Plan, _from_cursor: usize) -> Self::DueActions<'_> {
        PendingDueActions
    }
}

/// A signer that never signs. These tests reject the session from persisted
/// state before registration could complete, so it is never called.
struct NeverSigner;

impl Signer for NeverSigner {
    type Error = NeverError;

    async fn sign(&self, _psbt: Psbt) -> Result<Psbt, Self::Error> { Err(NeverError) }
}

#[tokio::test]
async fn execute_plan_rejects_empty_log_without_touching_mailbox() {
    let persister = InMemoryPersister::<MultipartySessionEvent>::default();
    let mailbox = CountingMailbox::default();

    let err = execute_plan(&mailbox, &PendingSchedule, &NeverSigner, &persister)
        .await
        .expect_err("an empty event log cannot be driven");

    assert!(matches!(err, DriverError::Replay(_)), "got {err:?}");
    assert_eq!(mailbox.reads.get(), 0);
    assert_eq!(mailbox.writes.get(), 0);
}

#[tokio::test]
async fn execute_plan_rejects_non_participant_session_without_touching_mailbox() {
    let persister = InMemoryPersister::<MultipartySessionEvent>::default();
    persister
        .save_event(MultipartySessionEvent::Closed(MultipartySessionOutcome::Failure))
        .expect("in-memory save is infallible");
    let mailbox = CountingMailbox::default();

    let err = execute_plan(&mailbox, &PendingSchedule, &NeverSigner, &persister)
        .await
        .expect_err("a closed session is not a participant with a plan");

    assert!(matches!(err, DriverError::UnexpectedState), "got {err:?}");
    assert_eq!(mailbox.reads.get(), 0);
    assert_eq!(mailbox.writes.get(), 0);
}
