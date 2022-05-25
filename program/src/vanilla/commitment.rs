use std::cmp::Ordering;

use solana_program::pubkey::Pubkey;

use crate::{params::{bn::Fr, rabin::{RABIN_MODULUS, RABIN_MODULUS_LEN}}, state::StateWrapper, bn::BigInteger};

pub fn is_commitment_valid(commitment: &[Fr]) -> bool {
    if commitment.len() != RABIN_MODULUS_LEN {
        return false;
    }

    let is_valid = commitment.iter().all(|c| c.is_valid());
    if is_valid {
        for (c, m) in commitment.iter().rev().zip(RABIN_MODULUS.iter().rev()) {
            match c.0.cmp(m) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
    }

    false
}

const COMMITMENT_LEN: usize = 32 * RABIN_MODULUS_LEN;

pub type Commitment = StateWrapper<Box<Vec<Fr>>, COMMITMENT_LEN>;

pub fn get_commitment_pda<'a>(
    pool: &'a Pubkey,
    leaf: &Fr,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], Vec<u8>, [u8; 1])) {
    let pool_ref = pool.as_ref();
    let leaf_ref = leaf.0.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref, &leaf_ref],
        program_id,
    );

    (key, (pool_ref, leaf_ref, [seed]))
}