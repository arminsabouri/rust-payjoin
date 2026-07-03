//! Driver-level tests that exercise the participant plan driver over a mock,
//! non-reqwest [`SharedMailbox`] — proving the loop is composable with a swapped
//! mailbox and the existing [`InMemoryPersister`]. The happy path (which needs
//! valid OHTTP/HPKE traffic) is covered end-to-end in the `payjoin` crate's
//! integration test against real test services.

use std::cell::Cell;
use std::pin::Pin;

use futures::{stream, Stream};
use payjoin::multiparty::{MultipartySessionEvent, MultipartySessionOutcome, Psbt};
use payjoin::persist::{InMemoryPersister, SessionPersister};
use payjoin_driver::participant::execute_plan;
use payjoin_driver::{CollaborativeMessageSet, DriverError};

/// A mailbox that records how many times it was read/written. The driver should
/// not reach it for sessions it can decide on from persisted state alone.
#[derive(Default)]
struct CountingMailbox {
    reads: Cell<usize>,
    writes: Cell<usize>,
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
    type Messages<'a> = Pin<Box<dyn Stream<Item = Result<Psbt, NeverError>> + 'a>>;

    async fn write(&self, _message: Psbt) -> Result<(), Self::Error> {
        self.writes.set(self.writes.get() + 1);
        Err(NeverError)
    }

    fn read(&self) -> Self::Messages<'_> {
        self.reads.set(self.reads.get() + 1);
        Box::pin(stream::empty())
    }
}

#[tokio::test]
async fn execute_plan_rejects_empty_log_without_touching_mailbox() {
    let persister = InMemoryPersister::<MultipartySessionEvent>::default();
    let mailbox = CountingMailbox::default();

    let err =
        execute_plan(&mailbox, &persister).await.expect_err("an empty event log cannot be driven");

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

    let err = execute_plan(&mailbox, &persister)
        .await
        .expect_err("a closed session is not a participant with a plan");

    assert!(matches!(err, DriverError::UnexpectedState), "got {err:?}");
    assert_eq!(mailbox.reads.get(), 0);
    assert_eq!(mailbox.writes.get(), 0);
}
