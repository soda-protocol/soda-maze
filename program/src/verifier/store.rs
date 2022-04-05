use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;

use crate::Packer;
use crate::params::{Fq, Fq2, G1Projective254, G1Affine254, G2HomProjective254, G2Affine254, Fqk254};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct StateWrapper<S: Clone + BorshSerialize + BorshDeserialize> {
    is_initialized: bool,
    state: S,
}

impl<S: Clone + BorshSerialize + BorshDeserialize> IsInitialized for StateWrapper<S> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<S: Clone + BorshSerialize + BorshDeserialize> Packer for StateWrapper<S> {
    const LEN: usize = 512;
}

impl<S: Clone + BorshSerialize + BorshDeserialize> AsRef<S> for StateWrapper<S> {
    fn as_ref(&self) -> &S {
        &self.state
    }
}

impl<S: Clone + BorshSerialize + BorshDeserialize> AsMut<S> for StateWrapper<S> {
    fn as_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

pub type G1ProjectiveWrapper = StateWrapper<G1Projective254>;

pub type G1AffineWrapper = StateWrapper<G1Affine254>;

pub type G2AffineWrapper = StateWrapper<G2Affine254>;

pub type G2HomProjectiveWrapper = StateWrapper<G2HomProjective254>;

pub type FqkWrapper = StateWrapper<Fqk254>;

pub type FqWrapper = StateWrapper<Fq>;

pub type Fq2Wrapper = StateWrapper<Fq2>;
