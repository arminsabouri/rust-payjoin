use bitcoin::key::rand::{thread_rng, RngCore};
use concurrent_psbt::constructor::Creator;
use concurrent_psbt::output::PSBT_OUT_UNIQUE_ID_SUBTYPE;
use serde::{Deserialize, Serialize};

use crate::receive::InputPair;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// TODO: add timestamp to when actions should be performed
pub enum Action {
    RegisterInput(InputPair),
    RegisterOutput { output: bitcoin::TxOut, unique_id: [u8; 32] },
}

impl Action {
    pub(crate) fn as_psbt_fragment(&self) -> psbt_v2::v2::Psbt {
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
