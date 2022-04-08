use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::pubkey::Pubkey;

use crate::{params::Fr, HEIGHT, bn::BigInteger256 as BigInteger};

pub const EMPTY_NODE_HASHES: &[Fr; 2] = &[
    Fr::new(BigInteger::new([0, 0, 0, 0])),
    Fr::new(BigInteger::new([0, 0, 0, 0])),
];

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct TreeNode {
    pub is_initialized: bool,
    pub hash: Fr,
}

#[inline]
pub fn find_tree_node_pda<'a>(
    pool: &'a Pubkey,
    layer: u8,
    index: u32,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1], [u8; 4], [u8; 1])) {
    let pool_ref = pool.as_ref();
    let layer_bytes = layer.to_le_bytes();
    let index_bytes = index.to_le_bytes();
    
    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref, &layer_bytes, &index_bytes],
        program_id,
    );

    (key, (pool_ref, layer_bytes, index_bytes, [seed]))
}


