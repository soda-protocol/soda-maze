use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, program_pack::IsInitialized};

use crate::{bn::{BigInteger, BigInteger256}, Packer};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Nullifier {
    is_initialized: bool,
    pub owner: Pubkey,
    pub used: bool,
}

impl Nullifier {
    pub fn new(owner: Pubkey) -> Self {
        Self {
            is_initialized: true,
            owner,
            used: false,
        }
    }
}

impl IsInitialized for Nullifier {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Nullifier {
    const LEN: usize = 1 + 1;
}

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
