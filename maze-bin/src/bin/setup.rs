use std::{path::Path, fs::OpenOptions};
use ark_serialize::CanonicalSerialize;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, proof::ConstParams};
use arkworks_utils::{utils::common::*, ark_std::rand::SeedableRng};
use structopt::StructOpt;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;
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

#[derive(Debug, StructOpt)]
#[structopt(name = "Maze Setup", about = "Soda Maze Setup Benchmark.")]
struct Opt {
    #[structopt(long, short = "c")]
    circuit: String,
    #[structopt(long = "leaf-params", default_value = "x3_5")]
    leaf_params: String,
    #[structopt(long = "inner-params", default_value = "x3_3")]
    inner_params: String,
    #[structopt(long = "no-seed")]
    no_seed: bool,
    #[structopt(long, short = "s", default_value = "")]
    seed: String,
    #[structopt(long = "pk-path")]
    pk_path: String,
    #[structopt(long = "vk-path")]
    vk_path: String,
}

fn main() {
    let opt = Opt::from_args();

    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    #[cfg(feature = "poseidon")]
    let (leaf_params, inner_params) = {
        let leaf_params = match opt.leaf_params.as_str() {
            "x3_5" => setup_params_x3_5::<Fr>(curve),
            "x5_4" => setup_params_x5_4::<Fr>(curve),
            "x5_5" => setup_params_x5_5::<Fr>(curve),
            _ => {
                println!("Unknown leaf params: {}", opt.leaf_params);
                return;
            }
        };
        let inner_params = match opt.inner_params.as_str() {
            "x3_3" => setup_params_x3_3::<Fr>(curve),
            "x3_5" => setup_params_x3_5::<Fr>(curve),
            "x5_3" => setup_params_x5_3::<Fr>(curve),
            "x5_4" => setup_params_x5_4::<Fr>(curve),
            "x5_5" => setup_params_x5_5::<Fr>(curve),
            _ => {
                println!("Unknown inner params: {}", opt.inner_params);
                return;
            }
        };

        (leaf_params, inner_params)
    };

    let mut rng = if opt.no_seed {
        XSRng(XorShiftRng::from_rng(OsRng).unwrap())
    } else {
        let mut seed = [0u8; 16];
        hex::decode_to_slice(opt.seed.as_bytes(), &mut seed).expect("invalid seed");
        XSRng(XorShiftRng::from_seed(seed))
    };

    let const_params = ConstParams { leaf_params, inner_params };
    let (pk, vk) = match opt.circuit.as_str() {
        "deposit" => DepositInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed"),
        "withdraw" => WithdrawInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed"),
        _ => panic!("Unknown circuit type: {}", opt.circuit)
    };

    let mut pk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(Path::new(&opt.pk_path))
        .expect("pk file open failed");
    pk.serialize(&mut pk_file).expect("pk serialize failed");

    println!("proving key write to {}", opt.pk_path);

    let mut vk_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(Path::new(&opt.vk_path))
        .expect("vk file open failed");
    vk.serialize(&mut vk_file).expect("vk serialize failed");

    println!("verifying key write to {}", opt.vk_path);
}
