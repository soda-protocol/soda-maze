use solana_program::pubkey::Pubkey;

use crate::state::StateWrapper;
use crate::bn::{BigInteger, BigInteger256};

pub type Nullifier = StateWrapper<(), 0>;

pub fn get_nullifier_pda<'a>(
    vault: &'a Pubkey,
    nullifier: &BigInteger256,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], Vec<u8>, [u8; 1])) {
    let vault_ref = vault.as_ref();
    let nullifier_ref = nullifier.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &nullifier_ref],
        program_id,
    );

    (key, (vault_ref, nullifier_ref, [seed]))
}
