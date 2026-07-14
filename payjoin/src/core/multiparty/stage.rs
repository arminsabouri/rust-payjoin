//! The sans-io session-stage contract shared by every multiparty state machine.
//!
//! Each stage is advanced by feeding it a decrypted [`Event`](SessionStage::Event)
//! reporting that some I/O the driver performed on the stage's behalf has
//! completed. The stage never performs transport itself; `step` returns the
//! persist [`Transition`](SessionStage::Transition) to save. The transition type
//! differs per stage (a single-log [`EventfulTransition`], the registry-based
//! graduation [`SessionParametersPollTransition`], or the plan's
//! [`ParticipantStepTransition`]), so it is an associated type rather than one
//! shared shape.

use crate::multiparty::initiator::{
    Initialized as InitiatorInitialized, Initiator, InitiatorEvent,
};
use crate::multiparty::participant::{
    HasPlan, Participant, ParticipantAwaitingEvent, ParticipantAwaitingSessionParameters,
    ParticipantEvent, ParticipantStepTransition,
};
use crate::multiparty::persist::{EventfulTransition, SessionParametersPollTransition};
use crate::multiparty::responder::{
    Initialized as ResponderInitialized, Responder, ResponderEvent,
};
use crate::multiparty::session::{MultipartySession, MultipartySessionEvent};
use crate::multiparty::session_creator::{CollectedSessions, SessionCreator, SessionCreatorEvent};
use crate::multiparty::{InitiatorSessionError, ResponderSessionError, SessionCreatorSessionError};

/// A sans-io multiparty session stage.
///
/// A stage is a state machine advanced by [`step`](SessionStage::step), which
/// consumes a decrypted [`Event`](SessionStage::Event) reporting completed I/O
/// and returns the persist [`Transition`](SessionStage::Transition) to save. It
/// performs no transport itself: the driver owns all I/O and reports its
/// completions as events.
pub trait SessionStage {
    /// Decrypted inbound event reporting that driver-performed I/O completed.
    type Event;
    /// The persist transition [`step`](Self::step) produces.
    type Transition;
    /// Advance the stage in response to one event, returning the transition to persist.
    fn step(&self, event: Self::Event) -> Self::Transition;
}

/// Single-log transition shared by the three bootstrap stages that never graduate.
type BootstrapTransition<Err> = EventfulTransition<MultipartySessionEvent, MultipartySession, Err>;

impl SessionStage for Responder<ResponderInitialized> {
    type Event = ResponderEvent;
    type Transition = BootstrapTransition<ResponderSessionError>;
    fn step(&self, event: Self::Event) -> Self::Transition { self.step(event) }
}

impl SessionStage for Initiator<InitiatorInitialized> {
    type Event = InitiatorEvent;
    type Transition = BootstrapTransition<InitiatorSessionError>;
    fn step(&self, event: Self::Event) -> Self::Transition { self.step(event) }
}

impl SessionStage for SessionCreator<CollectedSessions> {
    type Event = SessionCreatorEvent;
    type Transition = BootstrapTransition<SessionCreatorSessionError>;
    fn step(&self, event: Self::Event) -> Self::Transition { self.step(event) }
}

impl SessionStage for ParticipantAwaitingSessionParameters {
    type Event = ParticipantAwaitingEvent;
    // Adopting parameters is a graduation across two logs, so the transition is
    // saved against the registry rather than a single persister.
    type Transition = SessionParametersPollTransition;
    fn step(&self, event: Self::Event) -> Self::Transition { self.step(event) }
}

impl SessionStage for Participant<HasPlan> {
    type Event = ParticipantEvent;
    type Transition = ParticipantStepTransition;
    fn step(&self, event: Self::Event) -> Self::Transition { self.step(event) }
}
