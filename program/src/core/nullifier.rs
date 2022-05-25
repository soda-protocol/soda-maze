use solana_program::pubkey::Pubkey;

use crate::params::bn::Fr;
use crate::state::StateWrapper;
use crate::bn::BigInteger;

pub type Nullifier = StateWrapper<(), 0>;

pub fn get_nullifier_pda<'a>(
    vault: &'a Pubkey,
    nullifier: &Fr,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], Vec<u8>, [u8; 1])) {
    let vault_ref = vault.as_ref();
    let nullifier_ref = nullifier.0.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &nullifier_ref],
        program_id,
    );

    (key, (vault_ref, nullifier_ref, [seed]))
}
