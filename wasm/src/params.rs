use ark_bn254::{Fr, Bn254};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use soda_maze_program::params::HEIGHT;
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::withdraw::WithdrawConstParams;
use soda_maze_lib::vanilla::deposit::DepositConstParams;
use soda_maze_lib::vanilla::encryption::EncryptionConstParams;
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
use serde::{Serialize, Deserialize};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "resources/"]
pub struct Params;

#[derive(Serialize, Deserialize)]
pub struct RabinParameters {
    pub modulus: String,
    pub modulus_len: usize,
    pub bit_size: usize,
    pub cipher_batch: usize,
}

pub fn get_encryption_const_params() -> EncryptionConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::{params::poseidon::*, vanilla::encryption::biguint_to_biguint_array};

    let params = Params::get("rabin-param.json").unwrap();
    let params: RabinParameters = serde_json::from_reader(params.data.as_ref()).expect("failed to parse rabin-param.json");
    let modulus = hex::decode(&params.modulus).expect("modulus is an invalid hex string");
    let modulus = BigUint::from_bytes_le(&modulus);
    let modulus_array = biguint_to_biguint_array(modulus, params.modulus_len, params.bit_size);

    EncryptionConstParams {
        nullifier_params: get_poseidon_bn254_for_nullifier(),
        modulus_array,
        modulus_len: params.modulus_len,
        bit_size: params.bit_size,
        cipher_batch: params.cipher_batch,
    }
}

pub fn get_deposit_pk() -> ProvingKey<Bn254> {
    let params = Params::get("pk-deposit").unwrap();
    CanonicalDeserialize::deserialize(params.data.as_ref()).expect("failed to caninical deserialize pk-deposit")
}

pub fn get_withdraw_pk() -> ProvingKey<Bn254> {
    let params = Params::get("pk-withdraw").unwrap();
    CanonicalDeserialize::deserialize(params.data.as_ref()).expect("failed to caninical deserialize pk-withdraw")
}

pub fn get_deposit_const_params(params: EncryptionConstParams<Fr, PoseidonHasher<Fr>>) -> DepositConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;

    DepositConstParams {
        leaf_params: get_poseidon_bn254_for_leaf(),
        inner_params: get_poseidon_bn254_for_merkle(),
        height: HEIGHT,
        encryption: Some(params),
    }
}

pub fn get_withdraw_const_params() -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;
    
    WithdrawConstParams {
        nullifier_params: get_poseidon_bn254_for_nullifier(),
        leaf_params: get_poseidon_bn254_for_leaf(),
        inner_params: get_poseidon_bn254_for_merkle(),
        height: HEIGHT,
    }
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
            hash = PoseidonHasher::hash_two(params, hash, hash)
                .expect("poseidon hash error");
        });

    nodes
}
