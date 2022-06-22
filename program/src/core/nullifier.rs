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
    const LEN: usize = 1 + 32 + 1;
}

pub fn get_nullifier_pda<'a>(
    nullifier: &BigInteger256,
    program_id: &Pubkey,
) -> (Pubkey, (Vec<u8>, [u8; 1])) {
    let nullifier_vec = nullifier.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[&nullifier_vec],
        program_id,
    );

    (key, (nullifier_vec, [seed]))
}
