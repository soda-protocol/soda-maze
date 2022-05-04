pub mod fsm;
pub mod prepare_inputs;
pub mod miller_loop;
pub mod final_exponent;

use fsm::FSM;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;

use crate::{OperationType, Packer};
use crate::params::{G1Affine254, G2Affine254};

pub type ProofA = G1Affine254;

pub type ProofB = G2Affine254;

pub type ProofC = G1Affine254;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct StateWrapper<S: Clone + BorshSerialize + BorshDeserialize> {
    pub is_initialized: bool,
    pub state: S,
}

impl<S: Clone + BorshSerialize + BorshDeserialize> StateWrapper<S> {
    pub fn new(state: S) -> Self {
        Self {
            is_initialized: true,
            state,
        }
    }

    pub fn unwrap_state(self) -> S {
        self.state
    }
}

impl<S: Clone + BorshSerialize + BorshDeserialize> IsInitialized for StateWrapper<S> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<S: Clone + BorshSerialize + BorshDeserialize> Packer for StateWrapper<S> {
    const LEN: usize = 512;
}

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