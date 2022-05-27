use std::cmp::Ordering;
use solana_program::pubkey::Pubkey;

use crate::bn::BigInteger256;
use crate::params::rabin::{RABIN_MODULUS, RABIN_MODULUS_LEN};
use crate::{state::StateWrapper, bn::BigInteger};

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

const COMMITMENT_LEN: usize = 4 + 32 * RABIN_MODULUS_LEN;

pub type Commitment = StateWrapper<Box<Vec<BigInteger256>>, COMMITMENT_LEN>;

pub fn get_commitment_pda<'a>(
    vault: &'a Pubkey,
    leaf: &BigInteger256,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], Vec<u8>, [u8; 1])) {
    let vault_ref = vault.as_ref();
    let leaf_ref = leaf.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &leaf_ref],
        program_id,
    );

    (key, (vault_ref, leaf_ref, [seed]))
}