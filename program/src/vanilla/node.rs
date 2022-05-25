use solana_program::pubkey::Pubkey;

use crate::{params::{HEIGHT, bn::Fr}, state::StateWrapper};

/////////////////// Binary Merkle Tree //////////////////////////
///                         O                 ---------- root
///                  _____/   \_____       
///                 /               \
///                O                 O        ---------- Layer 2
///             __/ \__            __/\__ 
///            /       \          /      \
///           O         O        O        O   ---------- Layer 1
///          / \       / \      / \      / \
///         O   O     O   O    O   O    O   O ---------- Layer 0
///         0   1     2   3    4   5    6   7
///         |------------  index -----------|
/////////////////////////////////////////////////////////////////

#[inline]
pub fn gen_merkle_path_from_leaf_index(index: u64) -> Vec<(usize, u64)> {
    (0..HEIGHT).into_iter().map(|layer| (layer, index >> layer)).collect()
}

pub type TreeNode = StateWrapper<Fr, 32>;

pub fn get_tree_node_pda<'a>(
    pool: &'a Pubkey,
    layer: u8,
    index: u64,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1], [u8; 8], [u8; 1])) {
    let pool_ref = pool.as_ref();
    let layer_bytes = layer.to_le_bytes();
    let index_bytes = index.to_le_bytes();
    
    let (key, seed) = Pubkey::find_program_address(
        &[pool_ref, &layer_bytes, &index_bytes],
        program_id,
    );

    (key, (pool_ref, layer_bytes, index_bytes, [seed]))
}
