use std::fs::OpenOptions;
use std::path::PathBuf;
use ark_ec::AffineCurve;
use ark_groth16::PreparedVerifyingKey;
use arkworks_utils::utils::common::*;
use ark_serialize::{CanonicalSerialize, Write};
use ark_crypto_primitives::snark::*;
use rand_core::{CryptoRng, RngCore, SeedableRng, OsRng};
use rand_xorshift::XorShiftRng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json;
use structopt::StructOpt;
use num_bigint::BigUint;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::WithdrawProof};
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
use soda_maze_lib::vanilla::proof::WithdrawConstParams;
use soda_maze_lib::vanilla::rabin::RabinParam;

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr};

#[cfg(feature = "groth16")]
use ark_groth16::Groth16;

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

fn write_to_file<Se: CanonicalSerialize>(path: &PathBuf, data: &Se) {
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

    writeln!(&mut file, "use crate::{{params::{{G1Projective254, Fq, G1Affine254, EllCoeffFq2, Fq2, Fqk254, Fq6}}, bn::BigInteger256 as BigInteger}};\n")?;

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
    cypher_batch: usize,
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

#[cfg(feature = "poseidon")]
fn get_withdraw_const_params(height: usize, params: Option<RabinParameters>) -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    let rabin_param = params.map(|params| {
        let modulus = hex::decode(params.modulus).expect("modulus is an invalid hex string");
        RabinParam::new::<Fr>(
            BigUint::from_bytes_le(&modulus),
            params.modulus_len,
            params.bit_size,
            params.cypher_batch,
        )
    });

    WithdrawConstParams {
        secret_params: setup_params_x5_2::<Fr>(curve),
        nullifier_params: setup_params_x5_3::<Fr>(curve),
        leaf_params: setup_params_x5_4::<Fr>(curve),
        inner_params: setup_params_x3_3::<Fr>(curve),
        height,
        rabin_param,
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
        #[structopt(long = "cypher-batch", short = "c", default_value = "2")]
        cypher_batch: usize,
        #[structopt(long = "prime-path", parse(from_os_str))]
        prime_path: PathBuf,
        #[structopt(long = "param-path", parse(from_os_str))]
        param_path: PathBuf,
    },
    SetupCircuit {
        #[structopt(long, default_value = "26")]
        height: usize,
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "rabin-path", parse(from_os_str))]
        rabin_path: Option<PathBuf>,
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
            cypher_batch,
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

            let parameter = RabinParameters {
                modulus: hex::encode(modulus.to_bytes_le()),
                modulus_len: prime_len * 2,
                bit_size,
                cypher_batch,
            };
            write_json_to_file(&param_path, &parameter);
        },
        Opt::SetupCircuit {
            height,
            seed,
            rabin_path,
            pk_path,
            vk_path,
            pvk_path,
        } => {
            let params = rabin_path.map(|path| {
                let param: RabinParameters = read_json_from_file(&path);
                param
            });
            let const_params = get_withdraw_const_params(height, params);
            let mut rng = XSRng(get_xorshift_rng(seed));
            let (pk, vk) =
                WithdrawInstant::parameters_setup(&mut rng, &const_params).expect("parameters setup failed");

            write_to_file(&pk_path, &pk);
            write_to_file(&vk_path, &vk);

            let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk).unwrap();
            write_pvk_to_rust_file(&pvk_path, &pvk).expect("write pvk to file error");
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use ark_bn254::Fr;
//     use arkworks_utils::prelude::ark_ff::{BigInteger, PrimeField};
//     use num_bigint::BigUint;
//     use num_integer::Integer;
//     use soda_maze_lib::vanilla::rabin::{biguint_to_biguint_array};
    
//     #[test]
//     fn test() {
//         let modulus = "73d64eaa4e8dbcf2b871d1f672177ccdaa1625a61effe43545c2d82b9287f1d146c91f7bbf8a160a6e6b43dfb8c051d4647d88d415dbb570ed5576025c54294da9e7ef18d6cb04504c27f577d396a8c6a7b45488467b9c6b00eed26c907a3420b2e15394e0794882d04e3585657e2a7a4c09b0a65cb095477a68426c3ef136f35f5c71dac8f52031caf43b6e3da774166881702de0bf693d6df73c0f8d812fccf7edf919b687ee6fd5a0d7b2bda2549cff0f32cd62bec9399d9803cb589c9295a6b5b0bb74ed6acac1485f663072dd38b5679de6b58ebf05e20ae02d3f1cabaa1115dad1746c47313e2d0ebf7ccc6c1a00c8bd3cecb25c38aa37faae96b159dd2f471fd4e95a8656dd3a6f7d03aebb5b1a602f0fb4972b0b5c4d12243e255d4923b232ff4324158d044cd69cb3492740ab875d0adfe318c01294f82f239800b7d1fe274694706c7c67dbd71259531db06ba559353ebfd9cd078a43ee06d18de911ff10e5a2669d4243face8e7c12009cfd2705b4";
//         let modulus = hex::decode(modulus).expect("modulus is an invalid hex string");
//         let modulus = BigUint::from_bytes_le(&modulus);

//         let modulus_array = biguint_to_biguint_array(modulus, 24, 124);
//         modulus_array.chunks(2).for_each(|chunk| {
//             let val: BigUint = &chunk[0] + (&chunk[1] * (BigUint::from(1u64) << 124));

//             let val: Fr = val.into();
//             let val = val.into_repr();
//             println!("BigInteger::new({:?}),", &val.0);
//         });
//     }
// }