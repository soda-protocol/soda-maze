use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, program_pack::IsInitialized};

use crate::{params::{bn::Fr, default_nodes::DEFAULT_ROOT_HASH}, Packer};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Pool {
    pub is_initialized: bool,
    pub token_mint: Pubkey,
    pub authority: Pubkey,
    pub seed: [u8; 1],
    pub root: Fr,
    pub index: u64,
}

#[inline]
pub fn get_pool_authority_pda<'a>(
    pool: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1])) {
    let pool_ref = pool.as_ref();
    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref],
        program_id,
    );

    (key, (pool_ref, [seed]))
}

impl Pool {
    pub fn new(
        token_mint: Pubkey,
        pool: &Pubkey,
        program_id: &Pubkey,
    ) -> Self {
        let (authority, (_, seed)) = get_pool_authority_pda(pool, program_id);
        Self {
            is_initialized: true,
            token_mint,
            authority,
            seed,
            root: DEFAULT_ROOT_HASH,
            index: 0,
        }
    }

    pub fn update(&mut self, new_root: Fr, new_index: u64) {
        self.root = new_root;
        self.index = new_index;
    }
}

impl IsInitialized for Pool {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Pool {
    const LEN: usize = 1 + 32 + 32 + 1 + 32 + 8;
}
