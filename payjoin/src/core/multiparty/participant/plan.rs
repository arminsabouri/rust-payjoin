use core::fmt;
use std::time::Duration;

use bitcoin::key::rand::{thread_rng, Rng, RngCore};
use concurrent_psbt::constructor::{BothModifiable, Constructor, Creator};
use concurrent_psbt::output::PSBT_OUT_UNIQUE_ID_SUBTYPE;
use concurrent_psbt::sort::Unset;
use psbt_v2::v2::{DeserializeError, Psbt};
use serde::{Deserialize, Serialize};

use crate::receive::InputPair;

/// Error validating a mailbox payload as a concurrent PSBT fragment.
#[derive(Debug)]
pub enum PsbtFragmentError {
    Deserialize(DeserializeError),
    InvalidFragment(concurrent_psbt::constructor::ConstructorError),
}

impl fmt::Display for PsbtFragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deserialize(err) => write!(f, "invalid PSBT encoding: {err}"),
            Self::InvalidFragment(err) => write!(f, "invalid PSBT fragment: {err}"),
        }
    }
}

impl std::error::Error for PsbtFragmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deserialize(err) => Some(err),
            Self::InvalidFragment(err) => Some(err),
        }
    }
}

/// Parse one HPKE-decrypted mailbox payload into a validated PSBT fragment.
///
/// The mailbox transport calls this so parsing and validation live alongside
/// decryption, not in the participant state machine.
pub fn parse_mailbox_psbt_fragment(padded_message: &[u8]) -> Result<Psbt, PsbtFragmentError> {
    let bytes = trim_trailing_zeros(padded_message);
    let psbt = Psbt::deserialize(bytes).map_err(PsbtFragmentError::Deserialize)?;
    Constructor::<BothModifiable, Unset>::try_from_psbt(psbt.clone())
        .map_err(PsbtFragmentError::InvalidFragment)?;
    Ok(psbt)
}

fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &bytes[..end]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    RegisterInput(InputPair),
    RegisterOutput { output: bitcoin::TxOut, unique_id: [u8; 32] },
}

impl Action {
    pub(crate) fn as_psbt_fragment(&self) -> Psbt {
        match self {
            Action::RegisterInput(input) =>
                Creator::new().build().input(psbt_v2_input(input)).into_psbt(),
            Action::RegisterOutput { output, unique_id } => Creator::new()
                .build()
                .output(psbt_v2_output(output.clone(), *unique_id))
                .into_psbt(),
        }
    }
}

fn psbt_v2_input(input: &InputPair) -> psbt_v2::v2::Input {
    let sequence = input.txin.sequence;
    let mut psbt_input = psbt_v2::v2::Input::new(&input.txin.previous_output);
    psbt_input.sequence = Some(sequence);
    // Carry the spent UTXO so the accumulated PSBT can be valued: computing the
    // transaction's fee/balance needs each input's amount, which lives in the
    // funding-utxo field. Copy whichever the `InputPair` holds — `witness_utxo`
    // for segwit, `non_witness_utxo` for legacy — since both `psbt_v2`'s
    // `fee()` and `funding_utxo()` read either.
    psbt_input.witness_utxo = input.psbtin.witness_utxo.clone();
    psbt_input.non_witness_utxo = input.psbtin.non_witness_utxo.clone();
    psbt_input
}

// TODO: adding the uninque id should be part of the output() method in the concurrent-psbt crate
// Adding it externally here is a additional boilerplate.
fn psbt_v2_output(output: bitcoin::TxOut, unique_id: [u8; 32]) -> psbt_v2::v2::Output {
    let mut output = psbt_v2::v2::Output::new(output);
    let key = psbt_v2::raw::ProprietaryKey {
        prefix: b"concurrent-psbt".to_vec(),
        subtype: PSBT_OUT_UNIQUE_ID_SUBTYPE,
        key: vec![],
    };
    output.proprietaries.insert(key, unique_id.to_vec());
    output
}

// TODO: do we need a diff version of this for WASM target?
fn new_output_unique_id() -> [u8; 32] {
    let mut unique_id = [0u8; 32];
    thread_rng().fill_bytes(&mut unique_id);
    unique_id
}

/// Mean gap between consecutive plan actions. The Poisson process rate is
/// `1 / MEAN_ACTION_INTERVAL`. Tunable; not yet wire-configurable.
//TODO: make this configurable for different enviorments: test, dev, prod? And maybe a
// function of the session expiry if one exists
const MEAN_ACTION_INTERVAL: Duration = Duration::from_secs(5);

/// Sample one exponential inter-arrival gap by inverse transform:
/// `gap = -mean * ln(1 - u)`, with `u ~ Uniform[0, 1)`.
///
/// `rand` 0.8's `gen::<f64>()` yields `[0, 1)`, so `1 - u` is `(0, 1]` and
/// `ln` is always well defined (never `ln(0)`).
fn exp_gap<R: Rng>(rng: &mut R, mean: Duration) -> Duration {
    let u: f64 = rng.gen();
    mean.mul_f64(-(1.0 - u).ln())
}

/// A plan action paired with the time it should be sent to the shared mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledAction {
    /// Cumulative offset from plan start at which this action should be sent.
    pub send_at: Duration,
    pub action: Action,
}

pub(crate) struct PlanBuilder(Vec<Action>);

impl PlanBuilder {
    pub fn new() -> Self { Self(Vec::new()) }

    pub fn add_input(mut self, input: InputPair) -> Self {
        self.0.push(Action::RegisterInput(input));
        self
    }

    pub fn add_output(mut self, output: bitcoin::TxOut) -> Self {
        self.0.push(Action::RegisterOutput { output, unique_id: new_output_unique_id() });
        self
    }

    /// Assign each action a send time drawn from a Poisson process: the send
    /// time of action `i` is the running sum of exponential inter-arrival gaps
    /// through action `i` (the first action is itself exponentially delayed).
    pub fn build(self) -> Plan {
        let mut rng = thread_rng();
        let mut send_at = Duration::ZERO;
        let scheduled = self
            .0
            .into_iter()
            .map(|action| {
                send_at += exp_gap(&mut rng, MEAN_ACTION_INTERVAL);
                ScheduledAction { send_at, action }
            })
            .collect();
        Plan(scheduled)
    }
}

// Eventually this will be a tree of actions, but for now we just have a list of actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan(Vec<ScheduledAction>);

impl Plan {
    pub fn action(&self, index: usize) -> Option<&Action> {
        self.0.get(index).map(|scheduled| &scheduled.action)
    }

    /// Cumulative offset from plan start at which action `index` should be sent.
    pub fn send_at(&self, index: usize) -> Option<Duration> {
        self.0.get(index).map(|scheduled| scheduled.send_at)
    }

    pub fn len(&self) -> usize { self.0.len() }
}

#[cfg(test)]
mod tests {
    use bitcoin::key::rand::rngs::StdRng;
    use bitcoin::key::rand::SeedableRng;
    use bitcoin::TxOut;

    use super::{exp_gap, parse_mailbox_psbt_fragment, Action, PlanBuilder, MEAN_ACTION_INTERVAL};

    fn sample_txout() -> TxOut {
        TxOut { value: bitcoin::Amount::from_sat(10_000), script_pubkey: bitcoin::ScriptBuf::new() }
    }

    #[test]
    fn build_schedules_actions_with_monotonic_send_times() {
        let plan = PlanBuilder::new()
            .add_output(sample_txout())
            .add_output(sample_txout())
            .add_output(sample_txout())
            .build();

        assert_eq!(plan.len(), 3);
        let first = plan.send_at(0).expect("send time for action 0");
        assert!(first > std::time::Duration::ZERO, "first action is exponentially delayed");
        // Cumulative Poisson arrival times are strictly increasing.
        assert!(plan.send_at(1).expect("send time for action 1") > first);
        assert!(plan.send_at(2).expect("send time for action 2") > plan.send_at(1).unwrap());
        assert_eq!(plan.send_at(3), None);
    }

    #[test]
    fn exp_gap_matches_mean_over_many_samples() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 100_000;
        let total: f64 =
            (0..n).map(|_| exp_gap(&mut rng, MEAN_ACTION_INTERVAL).as_secs_f64()).sum();
        let sample_mean = total / f64::from(n);
        let expected = MEAN_ACTION_INTERVAL.as_secs_f64();
        // Inverse-transform of Exp(1/mean): the sample mean should sit within a
        // few percent of the true mean at this sample size.
        assert!(
            (sample_mean - expected).abs() < expected * 0.05,
            "sample mean {sample_mean} should be within 5% of {expected}"
        );
    }

    #[test]
    fn plan_action_accessor_still_returns_actions() {
        let output = sample_txout();
        let plan = PlanBuilder::new().add_output(output.clone()).build();
        // The scheduling wrapper is transparent: `action` still yields the
        // underlying `Action` at the requested index.
        match plan.action(0).expect("action at index 0") {
            Action::RegisterOutput { output: registered, .. } => assert_eq!(*registered, output),
            other => panic!("expected RegisterOutput, got {other:?}"),
        }
        assert_eq!(plan.action(1), None);
    }

    #[test]
    fn parse_mailbox_psbt_fragment_accepts_valid_fragment_with_padding() {
        let fragment = Action::RegisterOutput {
            output: TxOut {
                value: bitcoin::Amount::from_sat(42_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            unique_id: [1u8; 32],
        }
        .as_psbt_fragment();
        let mut padded = fragment.serialize();
        padded.extend(std::iter::repeat_n(0u8, 16));

        parse_mailbox_psbt_fragment(&padded).expect("valid padded PSBT fragment");
    }

    #[test]
    fn parse_mailbox_psbt_fragment_rejects_invalid_bytes() {
        assert!(parse_mailbox_psbt_fragment(b"not a psbt").is_err());
    }

    #[test]
    fn parse_mailbox_psbt_fragment_rejects_psbt_without_unique_id() {
        let psbt = concurrent_psbt::constructor::Creator::new().build().into_psbt();
        assert!(parse_mailbox_psbt_fragment(&psbt.serialize()).is_err());
    }
}
