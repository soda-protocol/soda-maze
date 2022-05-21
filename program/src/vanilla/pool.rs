use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;

use crate::params::bn::Fr;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Pool {
    pub is_initialized: bool,
    pub admin: Pubkey,
    pub authority: Pubkey,
    pub signer_seed: [u8; 1],
    pub root: Fr,
    pub index: u64,
}


