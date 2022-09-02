use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, program_pack::IsInitialized};

use crate::{Packer, bn::BigInteger};
use super::EdwardsAffine;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Nullifier {
    is_initialized: bool,
    pub receiver: Pubkey,
}

impl Nullifier {
    pub fn new(receiver: Pubkey) -> Self {
        Self {
            is_initialized: true,
            receiver,
        }
    }    
}

impl IsInitialized for Nullifier {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Nullifier {
    const LEN: usize = 1 + 32;
}

pub fn get_nullifier_pda(
    nullifier_point: &EdwardsAffine,
    program_id: &Pubkey,
) -> (Pubkey, (Vec<u8>, Vec<u8>, [u8; 1])) {
    let nullifier_x = nullifier_point.x.to_bytes_le();
    let nullifier_y = nullifier_point.y.to_bytes_le();

    let (key, seed) = Pubkey::find_program_address(
        &[&nullifier_x, &nullifier_y],
        program_id,
    );

    (key, (nullifier_x, nullifier_y, [seed]))
}
