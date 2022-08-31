use ark_bn254::Fr;
use ark_ed_on_bn254::EdwardsParameters;
use borsh::BorshDeserialize;
use rust_embed::RustEmbed;
use soda_maze_program::params::HEIGHT;

use soda_maze_lib::vanilla::hasher::{FieldHasher, poseidon::PoseidonHasher};
use soda_maze_lib::vanilla::withdraw::WithdrawConstParams;
use soda_maze_lib::vanilla::deposit::DepositConstParams;
use soda_maze_types::params::{gen_deposit_const_params, gen_withdraw_const_params};
use soda_maze_types::{keys::MazeProvingKey, parser::from_hex_string};

#[derive(RustEmbed)]
#[folder = "resources/"]
pub struct Params;

const VIEWING_PUBKEY: &str = "6242b1fcf0aa720c570854ae38e17f48cd24dd4d2a6ae359eb654c0059605098";

pub fn get_deposit_pk() -> MazeProvingKey {
    let params = Params::get("pk-deposit").unwrap();
    BorshDeserialize::deserialize(&mut params.data.as_ref()).unwrap()
}

pub fn get_withdraw_pk() -> MazeProvingKey {
    let params = Params::get("pk-withdraw").unwrap();
    BorshDeserialize::deserialize(&mut params.data.as_ref()).unwrap()
}

pub fn get_deposit_const_params() -> DepositConstParams<EdwardsParameters, PoseidonHasher<Fr>> {
    let pubkey = from_hex_string(VIEWING_PUBKEY.to_string()).unwrap();
    gen_deposit_const_params(
        HEIGHT,
        Some(pubkey),
    )
}

pub fn get_withdraw_const_params() -> WithdrawConstParams<EdwardsParameters, PoseidonHasher<Fr>> {
    let pubkey = from_hex_string(VIEWING_PUBKEY.to_string()).unwrap();
    gen_withdraw_const_params(
        HEIGHT,
        Some(pubkey),
    )
}

pub fn get_default_node_hashes() -> Vec<Fr> {
    use soda_maze_lib::params::poseidon::get_poseidon_bn254_for_merkle;

    let ref params = get_poseidon_bn254_for_merkle();
    let mut nodes = Vec::with_capacity(HEIGHT);
    let mut hash: Fr = PoseidonHasher::empty_hash();

    (0..HEIGHT)
        .into_iter()
        .for_each(|_| {
            nodes.push(hash);
            hash = PoseidonHasher::hash_two(params, hash, hash).unwrap();
        });

    nodes
}
