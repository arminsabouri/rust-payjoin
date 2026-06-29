use serde::{Deserialize, Serialize};

use crate::receive::InputPair;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// TODO: add timestamp to when actions should be performed
pub enum Action {
    RegisterInput(InputPair),
    RegisterOutput(bitcoin::TxOut),
}

impl Action {
    // HACK: we really want to be using the concurrent psbt library here.
    pub(crate) fn as_psbt_fragment(&self) -> bitcoin::Psbt {
        let tx = match self {
            Action::RegisterInput(input) => bitcoin::Transaction {
                input: vec![input.txin.clone()],
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                output: vec![],
            },
            Action::RegisterOutput(output) => bitcoin::Transaction {
                output: vec![output.clone()],
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
            },
        };

        bitcoin::Psbt::from_unsigned_tx(tx).unwrap()
    }
}

pub(crate) struct PlanBuilder(Vec<Action>);

impl PlanBuilder {
    pub fn new() -> Self { Self(Vec::new()) }

    pub fn add_input(mut self, input: InputPair) -> Self {
        self.0.push(Action::RegisterInput(input));
        self
    }

    pub fn add_output(mut self, output: bitcoin::TxOut) -> Self {
        self.0.push(Action::RegisterOutput(output));
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
