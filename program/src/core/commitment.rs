use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::Packer;
use crate::bn::{BigInteger256, BigInteger};
use super::{is_affine_valid, GroupAffine};

pub type InnerCommitment = (GroupAffine, GroupAffine);

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct Commitment {
    is_initialized: bool,
    pub inner: InnerCommitment,
}

impl Commitment {
    pub fn new(inner: InnerCommitment) -> Self {
        Commitment {
            is_initialized: true,
            inner,
        }
    }
}

impl IsInitialized for Commitment {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Commitment {
    const LEN: usize = 1 + 32 * 2 * 2;
}

#[inline]
pub fn is_commitment_valid(inner: &InnerCommitment) -> bool {
    is_affine_valid(&inner.0) && is_affine_valid(&inner.1)
}

pub fn get_commitment_pda<'a>(
    leaf: &BigInteger256,
    program_id: &Pubkey,
) -> (Pubkey, (Vec<u8>, [u8; 1])) {
    let leaf_vec = leaf.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[&leaf_vec],
        program_id,
    );

    (key, (leaf_vec, [seed]))
}