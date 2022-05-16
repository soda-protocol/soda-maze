use std::cmp::Ordering;
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;

use crate::{params::{Fr, RABIN_MODULUS, RABIN_FR_MODULUS_LEN}, bn::BigInteger};

pub fn is_credential_valid(credential: &[Fr]) -> bool {
    if credential.len() != RABIN_FR_MODULUS_LEN {
        return false;
    }

    let is_valid = credential.iter().all(|c| c.is_valid());
    if is_valid {
        for (c, m) in credential.iter().rev().zip(RABIN_MODULUS.iter().rev()) {
            match c.0.cmp(m) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
    }
    false
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Nullifier {
    pub is_initialized: bool,
    pub owner: Pubkey,
    pub credential: Vec<Fr>,
}

pub fn get_nullifier_pda<'a>(
    pool: &'a Pubkey,
    nullifier: &Fr,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], Vec<u8>, [u8; 1])) {
    let pool_ref = pool.as_ref();
    let nullifier_ref = nullifier.0.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref, &nullifier_ref],
        program_id,
    );

    (key, (pool_ref, nullifier_ref, [seed]))
}