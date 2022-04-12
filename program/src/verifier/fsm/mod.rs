mod processor;
mod fsm;

pub use processor::*;
pub use fsm::*;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;
use crate::{OperationType, Packer};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct VerifyState {
    pub is_initialized: bool,
    pub proof_type: OperationType,
    pub fsm: FSM,
}

impl IsInitialized for VerifyState {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for VerifyState {
    const LEN: usize = 256;
}

impl VerifyState {
    pub fn new(proof_type: OperationType, fsm: FSM) -> Self {
        Self {
            is_initialized: true,
            proof_type,
            fsm,
        }
    }
}