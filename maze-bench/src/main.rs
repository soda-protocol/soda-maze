use std::{path::PathBuf, fs::OpenOptions};
use ark_groth16::{ProvingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::proof::*;
use soda_maze_lib::vanilla::{array::Pubkey as ArrayPubkey, hasher::poseidon::PoseidonHasher, VanillaProof};
use soda_maze_lib::vanilla::proof::{DepositConstParams, WithdrawConstParams};
use arkworks_utils::{utils::common::*, ark_std::{UniformRand, rand::SeedableRng}};
use structopt::StructOpt;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;
use solana_program::pubkey::Pubkey;

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr};
#[cfg(feature = "groth16")]
use ark_groth16::Groth16;

const HEIGHT: u8 = 24;

#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>, HEIGHT>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>, HEIGHT>;
#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>, HEIGHT>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>, HEIGHT>;

#[cfg(all(feature = "poseidon"))]
type DepositVanillaInstant = DepositVanillaProof::<Fr, PoseidonHasher<Fr>, HEIGHT>;
#[cfg(all(feature = "poseidon"))]
type WithdrawVanillaInstant = WithdrawVanillaProof::<Fr, PoseidonHasher<Fr>, HEIGHT>;

fn read_from_file<De: CanonicalDeserialize>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    CanonicalDeserialize::deserialize(&file).expect("failed to parse friends")
}

fn read_from_hex<De: CanonicalDeserialize>(s: String) -> De {
    let buf = hex::decode(s).expect("failed to parse hex");
    CanonicalDeserialize::deserialize(&buf[..]).expect("failed to parse friends")
}

fn write_to_file<Se: CanonicalSerialize>(path: &PathBuf, data: &Se) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    data.serialize(&mut file).expect("serialize failed");
}

fn write_to_hex<Se: CanonicalSerialize>(data: &Se) -> String {
    let mut buf = Vec::new();
    data.serialize(&mut buf).expect("serialize failed");
    hex::encode(buf)
}

fn get_xorshift_rng(seed: Option<String>) -> XSRng {
    if let Some(seed) = seed {
        let mut s = [0u8; 16];
        hex::decode_to_slice(seed.as_bytes(), &mut s).expect("invalid seed");
        XSRng(XorShiftRng::from_seed(s))
    } else {
        XSRng(XorShiftRng::from_rng(OsRng).unwrap())
    }
}

#[cfg(feature = "poseidon")]
fn get_deposit_const_params() -> DepositConstParams<Fr, PoseidonHasher<Fr>> {
    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    DepositConstParams {
        leaf_params: setup_params_x5_4::<Fr>(curve),
        inner_params: setup_params_x5_3::<Fr>(curve),
    }
}

#[cfg(feature = "poseidon")]
fn get_withdraw_const_params() -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    WithdrawConstParams {
        nullifier_params: setup_params_x5_2(curve),
        leaf_params: setup_params_x5_4::<Fr>(curve),
        inner_params: setup_params_x5_3::<Fr>(curve),
    }
}

struct XSRng(XorShiftRng);

impl RngCore for XSRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for XSRng {}

#[derive(StructOpt)]
#[structopt(name = "Maze Setup", about = "Soda Maze Setup Benchmark.")]
enum Opt {
    SetupDeposit {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "pk-path", short = "pp", parse(from_os_str))]
        pk_path: PathBuf,
    },
    SetupWithdraw {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "pk-path", short = "pp", parse(from_os_str))]
        pk_path: PathBuf,
    },
    ProveDeposit {
        #[structopt(long = "pk-path", short = "pp", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "leaf-index", short = "li", default_value = "0")]
        leaf_index: u64,
        #[structopt(long, short = "m")]
        mint: Pubkey,
        #[structopt(long, short = "a")]
        amount: u64,
    },
    ProveWithdraw {
        #[structopt(long = "pk-path", short = "pp", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "friend-nodes", short = "fn")]
        friend_nodes: String,
        #[structopt(long = "leaf-index", short = "li", default_value = "0")]
        leaf_index: u64,
        #[structopt(long, short = "m")]
        mint: Pubkey,
        #[structopt(long = "deposit-amount", short = "da")]
        deposit_amount: u64,
        #[structopt(long = "withdraw-amount", short = "wa")]
        withdraw_amount: u64,
        #[structopt(long, short = "s")]
        secret: String,
    },
    VerifyDeposit {
        #[structopt(long = "verifying-key", short = "vk")]
        verifying_key: String,
        #[structopt(long, short = "p")]
        proof: String,
        #[structopt(long = "old-root", short = "or")]
        old_root: String,
        #[structopt(long = "new-leaf", short = "nl")]
        new_leaf: String,
        #[structopt(long = "update-nodes", short = "un")]
        update_nodes: String,
        #[structopt(long = "leaf-index", default_value = "0")]
        leaf_index: u64,
        #[structopt(long, short = "m")]
        mint: Pubkey,
        #[structopt(long, short = "a")]
        amount: u64,
    },
    VerifyWithdraw {
        #[structopt(long = "verifying-key", short = "vk")]
        verifying_key: String,
        #[structopt(long, short = "p")]
        proof: String,
        #[structopt(long, short = "r")]
        root: String,
        #[structopt(long, short = "n")]
        nullifier: String,
        #[structopt(long, short = "m")]
        mint: Pubkey,
        #[structopt(long = "withdraw-amount", short = "wa")]
        withdraw_amount: u64,
    },
}

fn main() {
    let opt = Opt::from_args();

    match opt {
        Opt::SetupDeposit { seed, pk_path } => {
            let const_params = get_deposit_const_params();
            let mut rng = get_xorshift_rng(seed);
            let (pk, vk) =
                DepositInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed");

            write_to_file(&pk_path, &pk);
            println!("proving key write to {:?}", pk_path);

            let vk_hex = write_to_hex(&vk);
            println!("verifying key: {:?}", vk_hex);
        },
        Opt::SetupWithdraw { seed, pk_path } => {
            let const_params = get_withdraw_const_params();
            let mut rng = get_xorshift_rng(seed);
            let (pk, vk) =
                WithdrawInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed");

            write_to_file(&pk_path, &pk);
            println!("proving key write to {:?}", pk_path);

            let vk_hex = write_to_hex(&vk);
            println!("verifying key: {:?}", vk_hex);
        },
        Opt::ProveDeposit {
            pk_path,
            seed,
            leaf_index,
            mint,
            amount,
        } => {
            let const_params = get_deposit_const_params();
            let friend_nodes = (0..HEIGHT).into_iter().map(|_| Fr::rand(&mut OsRng)).collect::<Vec<_>>();
            let friend_nodes_hex = write_to_hex(&friend_nodes);
            println!("friend nodes: {:?}", friend_nodes_hex);

            let secret = Fr::rand(&mut OsRng);
            let origin_inputs = DepositOriginInputs {
                friend_nodes,
                leaf_index,
                mint: ArrayPubkey::new(mint.to_bytes()),
                amount,
                secret,
            };
            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let mut rng = get_xorshift_rng(seed);
            let (pub_in, priv_in) = DepositVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
                .expect("generate vanilla proof failed");

            let update_nodes_hex = write_to_hex(&pub_in.update_nodes);
            println!("update nodes: {}", update_nodes_hex);
            println!("secret: {}", write_to_hex(&priv_in.secret));
            println!("old root: {}", write_to_hex(&pub_in.old_root));
            println!("new leaf: {}", write_to_hex(&pub_in.new_leaf));

            let proof = DepositInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk)
                .expect("generate snark proof failed");
            let mut proof_data = Vec::new();
            proof.serialize(&mut proof_data).expect("serialize proof failed");

            println!("proof: {}", hex::encode(proof_data));
        },
        Opt::ProveWithdraw {
            pk_path,
            seed,
            friend_nodes,
            leaf_index,
            mint,
            deposit_amount,
            withdraw_amount,
            secret,
        } => {
            let const_params = get_withdraw_const_params();
            let friend_nodes: Vec<Fr> = read_from_hex(friend_nodes);
            let secret = read_from_hex(secret);
            let origin_inputs = WithdrawOriginInputs {
                friend_nodes,
                leaf_index,
                mint: ArrayPubkey::new(mint.to_bytes()),
                deposit_amount,
                withdraw_amount,
                secret,
            };

            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let mut rng = get_xorshift_rng(seed);
            let (pub_in, priv_in) = WithdrawVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
                .expect("generate vanilla proof failed");

            println!("root: {:?}", write_to_hex(&pub_in.root));
            println!("nullifier: {:?}", write_to_hex(&pub_in.nullifier));

            let proof = WithdrawInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk)
                .expect("generate snark proof failed");
            let mut proof_data = Vec::new();
            proof.serialize(&mut proof_data).expect("serialize proof failed");
            
            println!("proof: {}", hex::encode(proof_data));
        },
        Opt::VerifyDeposit {
            verifying_key,
            proof,
            old_root,
            new_leaf,
            update_nodes,
            leaf_index,
            mint,
            amount,
        } => {
            let vk: VerifyingKey<_> = read_from_hex(verifying_key);
            let proof: Proof<_> = read_from_hex(proof);

            let pub_in = DepositPublicInputs {
                mint: ArrayPubkey::new(mint.to_bytes()),
                amount,
                old_root: read_from_hex(old_root),
                new_leaf: read_from_hex(new_leaf),
                leaf_index,
                update_nodes: read_from_hex(update_nodes),
            };

            let result = DepositInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify deposit proof success");
            } else {
                println!("verify deposit proof failed");
            }
        },
        Opt::VerifyWithdraw {
            verifying_key,
            proof,
            root,
            nullifier,
            mint,
            withdraw_amount,
        } => {
            let vk: VerifyingKey<_> = read_from_hex(verifying_key);
            let proof: Proof<_> = read_from_hex(proof);

            let pub_in = WithdrawPublicInputs {
                mint: ArrayPubkey::new(mint.to_bytes()),
                withdraw_amount,
                root: read_from_hex(root),
                nullifier: read_from_hex(nullifier),
            };

            let result = WithdrawInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify withdraw proof success");
            } else {
                println!("verify withdraw proof failed");
            }
        },
    }
}
