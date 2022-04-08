use borsh::{BorshSerialize, BorshDeserialize};
use concat_arrays::concat_arrays;
use solana_program::pubkey::Pubkey;

use crate::params::Fr;

pub mod pool;
pub mod vanilla;
pub mod node;

#[inline]
fn fr_to_bytes(nullifier: &Fr) -> [u8; 32] {
    concat_arrays!(
        nullifier.0.0[0].to_le_bytes(),
        nullifier.0.0[1].to_le_bytes(),
        nullifier.0.0[2].to_le_bytes(),
        nullifier.0.0[3].to_le_bytes(),
    )
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Nullifier(bool);

pub fn get_nullifier_pda<'a>(
    pool: &'a Pubkey,
    nullifier: &Fr,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 32], [u8; 1])) {
    let pool_ref = pool.as_ref();
    let nullifier_ref = fr_to_bytes(nullifier);

    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref, &nullifier_ref],
        program_id,
    );

    (key, (pool_ref, nullifier_ref, [seed]))
}