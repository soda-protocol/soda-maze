use std::{fs::OpenOptions, path::PathBuf, io::Write};
use borsh::BorshSerialize;
use ark_ff::PrimeField;
use ark_ec::AffineCurve;
use ark_groth16::PreparedVerifyingKey;
use ark_crypto_primitives::snark::*;
use rand_core::{CryptoRng, RngCore, SeedableRng, OsRng};
use rand_xorshift::XorShiftRng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json;
use structopt::StructOpt;
use num_bigint::BigUint;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
use soda_maze_lib::vanilla::deposit::DepositConstParams;
use soda_maze_lib::vanilla::withdraw::WithdrawConstParams;
use soda_maze_lib::vanilla::encryption::{EncryptionConstParams, biguint_to_biguint_array};
use soda_maze_keys::{MazeProvingKey, MazeVerifyingKey};

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr};

#[cfg(feature = "groth16")]
use ark_groth16::Groth16;

#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

fn read_json_from_file<De: DeserializeOwned>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    serde_json::from_reader(&file).expect("failed to parse file")
}

fn write_json_to_file<Se: Serialize>(path: &PathBuf, data: &Se) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, data)
        .expect("failed to write to file");
}

fn write_to_file<Se: BorshSerialize>(path: &PathBuf, data: &Se) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    data.serialize(&mut file).expect("serialize failed");
}

fn write_pvk_to_rust_file(path: &PathBuf, pvk: &PreparedVerifyingKey<Bn254>) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;

    writeln!(&mut file, "use crate::{{params::bn::{{G1Projective254, Fq, G1Affine254, EllCoeffFq2, Fq2, Fqk254, Fq6}}, bn::BigInteger256 as BigInteger}};\n")?;

    let g_ic_init = pvk.vk.gamma_abc_g1[0].into_projective();
    writeln!(&mut file, "pub const G_IC_INIT: &G1Projective254 = &G1Projective254::new_const(")?;
    writeln!(&mut file, "    Fq::new(BigInteger::new({:?})),", g_ic_init.x.0.0)?;
    writeln!(&mut file, "    Fq::new(BigInteger::new({:?})),", g_ic_init.y.0.0)?;
    writeln!(&mut file, "    Fq::new(BigInteger::new({:?})),", g_ic_init.z.0.0)?;
    writeln!(&mut file, ");\n")?;
        
    writeln!(&mut file, "pub const GAMMA_ABC_G1: &[G1Affine254] = &[")?;
    for g_ic in pvk.vk.gamma_abc_g1[1..].iter() {
        writeln!(&mut file, "    G1Affine254::new_const(")?;
        writeln!(&mut file, "        Fq::new(BigInteger::new({:?})),", g_ic.x.0.0)?;
        writeln!(&mut file, "        Fq::new(BigInteger::new({:?})),", g_ic.y.0.0)?;
        writeln!(&mut file, "        {}", g_ic.infinity)?;
        writeln!(&mut file, "    ),")?;
    }
    writeln!(&mut file, "];\n")?;

    writeln!(&mut file, "pub const ALPHA_G1_BETA_G2: &Fqk254 = &Fqk254::new_const(")?;
    writeln!(&mut file, "    Fq6::new_const(")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c0.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c0.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c1.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c1.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c2.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c2.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "    ),")?;
    writeln!(&mut file, "    Fq6::new_const(")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c0.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c0.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c1.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c1.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fq2::new_const(")?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c2.c0.0.0)?;
    writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c2.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "    ),")?;
    writeln!(&mut file, ");\n")?;

    writeln!(&mut file, "pub const GAMMA_G2_NEG_PC: &[EllCoeffFq2] = &[")?;
    for (a, b, c) in pvk.gamma_g2_neg_pc.ell_coeffs.iter() {
        writeln!(&mut file, "    (")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", a.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", a.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", b.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", b.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", c.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", c.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "    ),")?;
    }
    writeln!(&mut file, "];\n")?;

    writeln!(&mut file, "pub const DELTA_G2_NEG_PC: &[EllCoeffFq2] = &[")?;
    for (a, b, c) in pvk.delta_g2_neg_pc.ell_coeffs.iter() {
        writeln!(&mut file, "    (")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", a.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", a.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", b.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", b.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "        Fq2::new_const(")?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", c.c0.0.0)?;
        writeln!(&mut file, "            Fq::new(BigInteger::new({:?})),", c.c1.0.0)?;
        writeln!(&mut file, "        ),")?;
        writeln!(&mut file, "    ),")?;
    }
    writeln!(&mut file, "];")?;

    file.flush()
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

#[derive(Serialize, Deserialize)]
struct RabinPrimes {
    prime_a: String,
    prime_b: String,
}

#[derive(Serialize, Deserialize)]
struct RabinParameters {
    modulus: String,
    modulus_len: usize,
    bit_size: usize,
    cipher_batch: usize,
}

fn get_xorshift_rng(seed: Option<String>) -> XorShiftRng {
    if let Some(seed) = seed {
        let mut s = [0u8; 16];
        hex::decode_to_slice(seed.as_bytes(), &mut s).expect("invalid seed");
        XorShiftRng::from_seed(s)
    } else {
        XorShiftRng::from_rng(OsRng).unwrap()
    }
}

#[cfg(all(feature = "poseidon", feature = "bn254"))]
fn get_encryption_const_params(params: RabinParameters) -> EncryptionConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;

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

#[derive(StructOpt)]
#[structopt(name = "Soda Maze Gen Parameters", about = "Soda Maze Gen Parameters Benchmark.")]
enum Opt {
    GenRabinParam {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "bit-size", short = "b", default_value = "124")]
        bit_size: usize,
        #[structopt(long = "prime-len", short = "p", default_value = "12")]
        prime_len: usize,
        #[structopt(long = "cipher-batch", short = "c", default_value = "2")]
        cipher_batch: usize,
        #[structopt(long = "prime-path", parse(from_os_str))]
        prime_path: PathBuf,
        #[structopt(long = "param-path", parse(from_os_str))]
        param_path: PathBuf,
    },
    SetupDeposit {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long, default_value = "27")]
        height: usize,
        #[structopt(long = "rabin-path", parse(from_os_str))]
        rabin_path: Option<PathBuf>,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[structopt(long = "pvk-path", parse(from_os_str))]
        pvk_path: PathBuf,
    },
    SetupWithdraw {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long, default_value = "27")]
        height: usize,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[structopt(long = "pvk-path", parse(from_os_str))]
        pvk_path: PathBuf,
    },
}

fn main() {
    let opt = Opt::from_args();

    match opt {
        Opt::GenRabinParam {
            seed,
            bit_size,
            prime_len,
            cipher_batch,
            prime_path,
            param_path,
        } => {
            use num_bigint_dig::RandPrime;

            let mut rng = get_xorshift_rng(seed);
            let bit_len = bit_size * prime_len;
            let a = rng.gen_prime(bit_len);
            let b = rng.gen_prime(bit_len);
            let modulus = &a * &b;

            let primes = RabinPrimes {
                prime_a: hex::encode(a.to_bytes_le()),
                prime_b: hex::encode(b.to_bytes_le()),
            };
            write_json_to_file(&prime_path, &primes);
    
            let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());
            let modulus_array = biguint_to_biguint_array(modulus.clone(), prime_len * 2, bit_size);
            modulus_array.chunks(cipher_batch).for_each(|chunk| {
                let mut base = BigUint::from(1u64);
                let val = chunk.iter().fold(BigUint::from(0u64), |sum, s| {
                    let sum = &sum + s * &base;
                    base <<= bit_size;
                    sum
                });
                let val = Fr::from(val).into_repr();
                println!("    BigInteger::new({:?}),", &val.0);
            });

            let parameter = RabinParameters {
                modulus: hex::encode(modulus.to_bytes_le()),
                modulus_len: prime_len * 2,
                bit_size,
                cipher_batch,
            };
            write_json_to_file(&param_path, &parameter);
        },
        Opt::SetupDeposit {
            seed,
            height,
            rabin_path,
            pk_path,
            vk_path,
            pvk_path,
        } => {
            let const_params = rabin_path.map(|rabin_path| {
                let params: RabinParameters = read_json_from_file(&rabin_path);
                get_encryption_const_params(params)
            });
            let const_params = get_deposit_const_params(height, const_params);

            let mut rng = XSRng(get_xorshift_rng(seed));
            let (pk, vk) =
                DepositInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed");

            let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk).unwrap();
            write_pvk_to_rust_file(&pvk_path, &pvk).expect("write pvk to file error");

            let pk = MazeProvingKey::from(pk);
            let vk = MazeVerifyingKey::from(vk);

            write_to_file(&pk_path, &pk);
            write_to_file(&vk_path, &vk);
        }
        Opt::SetupWithdraw {
            height,
            seed,
            pk_path,
            vk_path,
            pvk_path,
        } => {
            let const_params = get_withdraw_const_params(height);
            
            let mut rng = XSRng(get_xorshift_rng(seed));
            let (pk, vk) =
                WithdrawInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed");

            let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk).unwrap();
            write_pvk_to_rust_file(&pvk_path, &pvk).expect("write pvk to file error");

            let pk = MazeProvingKey::from(pk);
            let vk = MazeVerifyingKey::from(vk);
            
            write_to_file(&pk_path, &pk);
            write_to_file(&vk_path, &vk);
        }
    }
}