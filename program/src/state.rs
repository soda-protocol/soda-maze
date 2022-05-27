use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;

use crate::Packer;

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
