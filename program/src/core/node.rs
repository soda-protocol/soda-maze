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
pub fn is_updating_nodes_valid(nodes: &[Fr]) -> bool {
    if nodes.len() != HEIGHT {
        false
    } else {
        nodes.iter().all(|x| x.is_valid())
    }
}

#[inline]
pub fn gen_merkle_path_from_leaf_index(index: u64) -> Vec<(usize, u64)> {
    (0..HEIGHT).into_iter().map(|layer| (layer, index >> layer)).collect()
}

pub fn get_tree_node_pda<'a>(
    vault: &'a Pubkey,
    layer: usize,
    index: u64,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 8], [u8; 8], [u8; 1])) {
    let vault_ref = vault.as_ref();
    let layer_bytes = layer.to_le_bytes();
    let index_bytes = index.to_le_bytes();
    
    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &layer_bytes, &index_bytes],
        program_id,
    );

    (key, (vault_ref, layer_bytes, index_bytes, [seed]))
}

pub type MerkleNode = StateWrapper<Fr, 32>;
