use core::fmt;

use bitcoin::key::rand::{thread_rng, RngCore};
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
// TODO: add timestamp to when actions should be performed
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

fn new_output_unique_id() -> [u8; 32] {
    let mut unique_id = [0u8; 32];
    thread_rng().fill_bytes(&mut unique_id);
    unique_id
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

    pub fn build(self) -> Plan { Plan(self.0) }
}

// Eventually this will be a tree of actions, but for now we just have a list of actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan(Vec<Action>);

impl Plan {
    pub fn action(&self, index: usize) -> Option<&Action> { self.0.get(index) }
    pub fn len(&self) -> usize { self.0.len() }
}

#[cfg(test)]
mod tests {
    use bitcoin::TxOut;

    use super::{parse_mailbox_psbt_fragment, Action};

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
