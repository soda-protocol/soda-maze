use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

use crate::Packer;

pub fn get_utxo_pda<'a>(
    utxo: &'a [u8],
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1])) {
    let (key, seed) = Pubkey::find_program_address(
        &[utxo],
        program_id,
    );

    (key, (utxo, [seed]))
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum Amount {
    Origin(u64),
    Cipher(u128),
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct UTXO {
    is_initialized: bool,
    pub leaf_index: u64,
    pub amount: Amount,
}

impl UTXO {
    pub fn new(leaf_index: u64, amount: Amount) -> Self {
        Self {
            is_initialized: true,
            leaf_index,
            amount,
        }
    }
}

impl IsInitialized for UTXO {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for UTXO {
    const LEN: usize = 1 + 8 + 1 + 16;
}
