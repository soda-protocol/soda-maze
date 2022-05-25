use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;

use crate::{Packer, params::proof::ProofType};
use crate::verifier::fsm::FSM;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct VerifyState {
    pub is_initialized: bool,
    pub proof_type: ProofType,
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
    pub fn new(proof_type: ProofType, fsm: FSM) -> Self {
        Self {
            is_initialized: true,
            proof_type,
            fsm,
        }
    }
}

pub type StateWrapper512<S> = StateWrapper<S, 512>;
pub type StateWrapper1024<S> = StateWrapper<S, 1024>;
pub type StateWrapper2048<S> = StateWrapper<S, 2048>;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct StateWrapper<S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> {
    is_initialized: bool,
    state: S,
}

impl<S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> StateWrapper<S, LEN> {
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

impl<S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> IsInitialized for StateWrapper<S, LEN> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<S: Clone + BorshSerialize + BorshDeserialize, const LEN: usize> Packer for StateWrapper<S, LEN> {
    const LEN: usize = 1 + LEN;
}
