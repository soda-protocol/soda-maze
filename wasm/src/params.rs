use std::{path::PathBuf, fs::OpenOptions};
use ark_bn254::{Fr, Bn254};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use lazy_static::lazy_static;
use soda_maze_program::params::HEIGHT;
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::withdraw::WithdrawConstParams;
use soda_maze_lib::vanilla::deposit::DepositConstParams;
use soda_maze_lib::vanilla::encryption::EncryptionConstParams;
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
use serde::{Serialize, Deserialize, de::DeserializeOwned};

const RABIN_PATH: &str = "../resources/rabin_params.json";
const DEPOSIT_PK_PATH: &str = "../resources/pk-deposit";
const WITHDRAW_PK_PATH: &str = "../resources/pk-withdraw";

pub fn read_json_from_file<De: DeserializeOwned>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    serde_json::from_reader(&file).expect("failed to parse json file")
}

fn read_from_file<De: CanonicalDeserialize>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    CanonicalDeserialize::deserialize(&file).expect("failed to parse file")
}

fn get_encryption_const_params(params: RabinParameters) -> EncryptionConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::{params::poseidon::*, vanilla::encryption::biguint_to_biguint_array};

    let modulus = hex::decode(params.modulus).expect("modulus is an invalid hex string");
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

#[derive(Serialize, Deserialize)]
struct RabinParameters {
    modulus: String,
    modulus_len: usize,
    bit_size: usize,
    cipher_batch: usize,
}

lazy_static! {
    pub static ref ENCRYPTION_CONST_PARAMS: EncryptionConstParams<Fr, PoseidonHasher<Fr>> = {
        let params: RabinParameters = read_json_from_file(&PathBuf::from(RABIN_PATH));
        get_encryption_const_params(params)
    };

    pub static ref DEPOSIT_CONST_PARAMS: DepositConstParams<Fr, PoseidonHasher<Fr>> = {
        use soda_maze_lib::params::poseidon::*;

        let params: RabinParameters = read_json_from_file(&PathBuf::from(RABIN_PATH));
        let params = get_encryption_const_params(params);

        DepositConstParams {
            leaf_params: get_poseidon_bn254_for_leaf(),
            inner_params: get_poseidon_bn254_for_merkle(),
            height: HEIGHT,
            encryption: Some(params),
        }
    };

    pub static ref WITHDRAW_CONST_PARAMS: WithdrawConstParams<Fr, PoseidonHasher<Fr>> = {
        use soda_maze_lib::params::poseidon::*;
    
        WithdrawConstParams {
            nullifier_params: get_poseidon_bn254_for_nullifier(),
            leaf_params: get_poseidon_bn254_for_leaf(),
            inner_params: get_poseidon_bn254_for_merkle(),
            height: HEIGHT,
        }
    };

    pub static ref DEPOSIT_PK: ProvingKey<Bn254> = read_from_file(&PathBuf::from(DEPOSIT_PK_PATH));

    pub static ref WITHDRAW_PK: ProvingKey<Bn254> = read_from_file(&PathBuf::from(WITHDRAW_PK_PATH));

    pub static ref DEFAULT_NODE_HASHES: Vec<Fr> = {
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
    };
}

