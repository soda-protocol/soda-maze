use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::{path::PathBuf, fs::OpenOptions};
use ark_ff::{FpParameters, PrimeField};
use ark_std::{UniformRand, rand::SeedableRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read};
use borsh::BorshDeserialize;
use clap::{Parser, Command, Arg, value_t};
use arkworks_utils::poseidon::PoseidonParameters;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::withdraw::{WithdrawConstParams, WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::deposit::{DepositConstParams, DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::encryption::{EncryptionConstParams, EncryptionPublicInputs, EncryptionOriginInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};
use soda_maze_keys::{MazeProvingKey, MazeVerifyingKey};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use soda_maze_program::ID;
use soda_maze_program::core::{node::get_merkle_node_pda, commitment::get_commitment_pda};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, signature::Signature};
use solana_transaction_status::UiTransactionEncoding;

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr, FrParameters};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr, FrParameters};
#[cfg(feature = "groth16")]
use ark_groth16::Groth16;

#[derive(Serialize, Deserialize)]
struct RabinParameters {
    modulus: String,
    modulus_len: usize,
    bit_size: usize,
    cipher_batch: usize,
}

fn read_json_from_file<De: DeserializeOwned>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    serde_json::from_reader(&file).expect("failed to parse file")
}

#[cfg(all(feature = "poseidon", feature = "bn254"))]
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

#[cfg(all(feature = "poseidon", feature = "bn254"))]
fn get_deposit_const_params(
    height: usize,
    encryption: Option<EncryptionConstParams<Fr, PoseidonHasher<Fr>>>,
) -> DepositConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;

    DepositConstParams {
        leaf_params: get_poseidon_bn254_for_leaf(),
        inner_params: get_poseidon_bn254_for_merkle(),
        height,
        encryption,
    }
}

#[cfg(all(feature = "poseidon", feature = "bn254"))]
fn get_withdraw_const_params(height: usize) -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;
    
    WithdrawConstParams {
        nullifier_params: get_poseidon_bn254_for_nullifier(),
        leaf_params: get_poseidon_bn254_for_leaf(),
        inner_params: get_poseidon_bn254_for_merkle(),
        height,
    }
}

#[derive(Parser, Debug)]
#[clap(version = "0.0.1", about = "Soda Maze Eye", long_about = "")]
struct Args {
    #[clap(short, long, value_parser, default_value = "https://api.devnet.solana.com")]
    url: String,
    #[clap(short, long, value_parser)]
    vault: String,
    #[clap(short, long, value_parser)]
    index: u64,
    #[clap(short, long, value_parser)]
    signature: String,
}

fn main() {
    let ref args = Args::parse();
    
    let client = &RpcClient::new_with_commitment(
        args.url,
        CommitmentConfig::finalized(),
    );
    let sig = Signature::from_str(&args.signature).expect("invalid signature");
    client.get_transaction(&sig, UiTransactionEncoding::JsonParsed)


    let matches = Command::new("Soda Maze Eye")
        .version("0.1")
        .arg(
            Arg::with_name("url")
                .short('u')
                .help("Solana rpc url")
                .default_value("https://api.devnet.solana.com")
        )
        .arg(
            Arg::with_name("vault")
                .short('v')
                .help("Vault pubkey")
                .required(true)
        )
        .arg(
            Arg::with_name("index")
                .short('i')
                .help("Leaf node index in Merkle tree")
                .required(true)
        );
    
    

    let url = value_t!(matches, "url", String)?;
    let vault = value_t!(matches, "vault", String)?;

    let client = &RpcClient::new_with_commitment(
        url,
        CommitmentConfig::finalized(),
    );

    Ok(())
}
