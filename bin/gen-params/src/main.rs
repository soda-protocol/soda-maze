use std::{fs::OpenOptions, path::PathBuf, io::{Write, Result}};
use ark_ec::{AffineCurve, ProjectiveCurve, models::twisted_edwards_extended::{GroupAffine, GroupProjective}};
use ark_ff::{PrimeField, UniformRand};
use ark_crypto_primitives::snark::*;
use ark_groth16::{Groth16, PreparedVerifyingKey};
use clap::Parser;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_types::keys::{MazeProvingKey, MazeVerifyingKey};
use soda_maze_types::parser::{to_hex_string, from_hex_string, borsh_se_to_file};
use soda_maze_types::params::{gen_deposit_const_params, gen_withdraw_const_params};
use soda_maze_types::rand::get_xorshift_rng;

#[cfg(feature = "poseidon")]
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
#[cfg(feature = "poseidon")]
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr};
#[cfg(feature = "bn254")]
use ark_ed_on_bn254::{EdwardsParameters, Fr as Frr};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr};
#[cfg(feature = "bls12-381")]
use ark_ed_on_bls12_381::{EdwardsParameters, Fr as Frr};

#[cfg(all(feature = "bn254", feature = "poseidon"))]
type DepositInstant = DepositProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon"))]
type DepositInstant = DepositProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

#[cfg(all(feature = "bn254", feature = "poseidon"))]
type WithdrawInstant = WithdrawProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon"))]
type WithdrawInstant = WithdrawProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

#[cfg(feature = "bn254")]
fn write_pvk_to_rust_file(path: &PathBuf, pvk: &PreparedVerifyingKey<Bn254>) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;

    writeln!(&mut file, "use crate::{{params::bn::{{G1Projective254, Fr, G1Affine254, G2Prepared254, Fr2, Frk254, Fr6}}, bn::BigInteger256 as BigInteger}};\n")?;

    let g_ic_init = pvk.vk.gamma_abc_g1[0].into_projective();
    writeln!(&mut file, "pub const G_IC_INIT: &G1Projective254 = &G1Projective254::new_const(")?;
    writeln!(&mut file, "    Fr::new(BigInteger::new({:?})),", g_ic_init.x.0.0)?;
    writeln!(&mut file, "    Fr::new(BigInteger::new({:?})),", g_ic_init.y.0.0)?;
    writeln!(&mut file, "    Fr::new(BigInteger::new({:?})),", g_ic_init.z.0.0)?;
    writeln!(&mut file, ");\n")?;
        
    writeln!(&mut file, "pub const GAMMA_ABC_G1: &[G1Affine254] = &[")?;
    for g_ic in pvk.vk.gamma_abc_g1[1..].iter() {
        writeln!(&mut file, "    G1Affine254::new_const(")?;
        writeln!(&mut file, "        Fr::new(BigInteger::new({:?})),", g_ic.x.0.0)?;
        writeln!(&mut file, "        Fr::new(BigInteger::new({:?})),", g_ic.y.0.0)?;
        writeln!(&mut file, "        {},", g_ic.infinity)?;
        writeln!(&mut file, "    ),")?;
    }
    writeln!(&mut file, "];\n")?;

    writeln!(&mut file, "pub const ALPHA_G1_BETA_G2: &Frk254 = &Frk254::new_const(")?;
    writeln!(&mut file, "    Fr6::new_const(")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c0.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c0.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c1.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c1.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c2.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c0.c2.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "    ),")?;
    writeln!(&mut file, "    Fr6::new_const(")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c0.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c0.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c1.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c1.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "        Fr2::new_const(")?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c2.c0.0.0)?;
    writeln!(&mut file, "            Fr::new(BigInteger::new({:?})),", pvk.alpha_g1_beta_g2.c1.c2.c1.0.0)?;
    writeln!(&mut file, "        ),")?;
    writeln!(&mut file, "    ),")?;
    writeln!(&mut file, ");\n")?;

    writeln!(&mut file, "pub const GAMMA_G2_NEG_PC: &G2Prepared254 = &G2Prepared254 {{")?;
    writeln!(&mut file, "    ell_coeffs: &[")?;
    for (a, b, c) in pvk.gamma_g2_neg_pc.ell_coeffs.iter() {
        writeln!(&mut file, "        (")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", a.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", a.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", b.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", b.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", c.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", c.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "       ),")?;
    }
    writeln!(&mut file, "    ],")?;
    writeln!(&mut file, "    infinity: {},", pvk.gamma_g2_neg_pc.infinity)?;
    writeln!(&mut file, "}};\n")?;

    writeln!(&mut file, "pub const DELTA_G2_NEG_PC: &G2Prepared254 = &G2Prepared254 {{")?;
    writeln!(&mut file, "    ell_coeffs: &[")?;
    for (a, b, c) in pvk.delta_g2_neg_pc.ell_coeffs.iter() {
        writeln!(&mut file, "        (")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", a.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", a.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", b.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", b.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "            Fr2::new_const(")?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", c.c0.0.0)?;
        writeln!(&mut file, "                Fr::new(BigInteger::new({:?})),", c.c1.0.0)?;
        writeln!(&mut file, "            ),")?;
        writeln!(&mut file, "        ),")?;
    }
    writeln!(&mut file, "    ],")?;
    writeln!(&mut file, "    infinity: {},", pvk.delta_g2_neg_pc.infinity)?;
    writeln!(&mut file, "}};")?;

    file.flush()
}

#[derive(Parser, Debug)]
#[clap(name = "Soda Maze Gen Parameters", version = "0.0.1", about = "Soda Maze Gen Parameters Benchmark.", long_about = "")]
enum Opt {
    GenViewingKey {
        #[clap(long, short = 's', value_parser)]
        seed: Option<String>,
    },
    SetupDeposit {
        #[clap(long, short = 's', value_parser)]
        seed: Option<String>,
        #[clap(long, value_parser, default_value = "21")]
        height: usize,
        #[clap(long = "viewing-pubkey", value_parser)]
        pubkey: Option<String>,
        #[clap(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[clap(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[clap(long = "pvk-path", parse(from_os_str))]
        pvk_path: PathBuf,
    },
    SetupWithdraw {
        #[clap(long, short = 's', value_parser)]
        seed: Option<String>,
        #[clap(long, value_parser, default_value = "21")]
        height: usize,
        #[clap(long = "viewing-pubkey", value_parser)]
        pubkey: Option<String>,
        #[clap(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[clap(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[clap(long = "pvk-path", parse(from_os_str))]
        pvk_path: PathBuf,
    },
}

fn main() {
    let opt = Opt::parse();

    match opt {
        Opt::GenViewingKey { seed } => {
            let rng = &mut get_xorshift_rng(seed);

            let privkey = Frr::rand(rng);
            let privkey_int: <Frr as PrimeField>::BigInt = privkey.into();
            let generator = GroupProjective::<EdwardsParameters>::prime_subgroup_generator();
            let pubkey: GroupAffine<_> = generator.mul(&privkey_int).into();

            println!("private key: {}", to_hex_string(&privkey).unwrap());
            println!("public key: {}", to_hex_string(&pubkey).unwrap());
        },
        Opt::SetupDeposit {
            seed,
            height,
            pubkey,
            pk_path,
            vk_path,
            pvk_path,
        } => {
            let pubkey = pubkey.map(|pubkey| {
                from_hex_string::<GroupAffine<EdwardsParameters>>(pubkey).expect("invalid viewing pubkey")
            });
            let const_params = gen_deposit_const_params(
                height,
                pubkey,
            );

            let rng = &mut get_xorshift_rng(seed);
            let (pk, vk) =
                DepositInstant::parameters_setup(rng, &const_params).expect("parameters setup failed");

            let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk).unwrap();
            write_pvk_to_rust_file(&pvk_path, &pvk).expect("write pvk to file error");

            let pk = MazeProvingKey::from(pk);
            let vk = MazeVerifyingKey::from(vk);

            borsh_se_to_file(&pk, &pk_path).unwrap();
            borsh_se_to_file(&vk, &vk_path).unwrap();
        }
        Opt::SetupWithdraw {
            height,
            seed,
            pubkey,
            pk_path,
            vk_path,
            pvk_path,
        } => {
            let pubkey = pubkey.map(|pubkey| {
                from_hex_string::<GroupAffine<EdwardsParameters>>(pubkey).expect("invalid viewing pubkey")
            });
            let const_params = gen_withdraw_const_params(
                height,
                pubkey,
            );
            
            let rng = &mut get_xorshift_rng(seed);
            let (pk, vk) =
                WithdrawInstant::parameters_setup(rng, &const_params).expect("parameters setup failed");

            let pvk = <Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk).unwrap();
            write_pvk_to_rust_file(&pvk_path, &pvk).expect("write pvk to file error");

            let pk = MazeProvingKey::from(pk);
            let vk = MazeVerifyingKey::from(vk);
            
            borsh_se_to_file(&pk, &pk_path).unwrap();
            borsh_se_to_file(&vk, &vk_path).unwrap();
        }
    }
}
