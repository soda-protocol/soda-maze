use std::cmp::Ordering;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::Packer;
use crate::bn::{BigInteger256, BigInteger};
use crate::params::rabin::{RABIN_MODULUS, RABIN_MODULUS_LEN};
use super::is_fr_valid;

pub fn is_commitment_valid(commitment: &[BigInteger256]) -> bool {
    if commitment.len() != RABIN_MODULUS_LEN {
        return false;
    }

    let is_valid = commitment.iter().all(|c| is_fr_valid(c));
    if is_valid {
        for (c, m) in commitment.iter().rev().zip(RABIN_MODULUS.iter().rev()) {
            match c.cmp(m) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
    }

    false
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct Commitment {
    is_initialized: bool,
    pub cipher: Box<Vec<BigInteger256>>,
}

impl Commitment {
    pub fn new(cipher: Box<Vec<BigInteger256>>) -> Self {
        Commitment {
            is_initialized: true,
            cipher,
        }
    }
}

impl IsInitialized for Commitment {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Commitment {
    const LEN: usize = 1 + 4 + 32 * RABIN_MODULUS_LEN;
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