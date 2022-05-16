use std::collections::BTreeMap;
use std::{path::PathBuf, fs::OpenOptions};
use ark_ff::FpParameters;
use ark_std::{UniformRand, rand::SeedableRng};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use arkworks_utils::poseidon::PoseidonParameters;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::proof::*;
use soda_maze_lib::vanilla::{array::Pubkey as ArrayPubkey, hasher::poseidon::PoseidonHasher, VanillaProof};
use soda_maze_lib::vanilla::proof::{DepositConstParams, WithdrawConstParams};
use arkworks_utils::utils::common::*;
use structopt::StructOpt;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use solana_program::pubkey::Pubkey;

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr, FrParameters};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr, FrParameters};
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

#[cfg(all(feature = "poseidon"))]
type DepositVanillaInstant = DepositVanillaProof::<Fr, PoseidonHasher<Fr>>;
#[cfg(all(feature = "poseidon"))]
type WithdrawVanillaInstant = WithdrawVanillaProof::<Fr, PoseidonHasher<Fr>>;

#[derive(Serialize, Deserialize)]
struct RabinParameters {
    modulus: String,
    modulus_len: usize,
    bit_size: usize,
    cypher_batch: usize,
}

#[derive(Serialize, Deserialize)]
struct DepositProofData {
    height: usize,
    mint: Pubkey,
    amount: u64,
    leaf_index: u64,
    old_root: String,
    new_leaf: String,
    update_nodes: Vec<String>,
    proof: String,
}

#[derive(Serialize, Deserialize)]
struct WithdrawProofData {
    mint: Pubkey,
    withdraw_amount: u64,
    nullifier: String,
    old_root: String,
    new_leaf_index: u64,
    new_leaf: String,
    update_nodes: Vec<String>,
    cypher: Option<Vec<String>>,
    proof: String,
}

#[derive(Serialize, Deserialize)]
struct WithdrawInputs {
    height: usize,
    mint: Pubkey,
    deposit_amount: u64,
    withdraw_amount: u64,
    nullifier: String,
    old_root: String,
    new_leaf_index: u64,
    new_leaf: String,
    update_nodes: Vec<String>,
    cypher: Option<Vec<String>>,
    proof: String,
}

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

fn read_from_file<De: CanonicalDeserialize>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    CanonicalDeserialize::deserialize(&file).expect("failed to parse file")
}

fn from_hex<De: CanonicalDeserialize>(s: String) -> De {
    let buf = hex::decode(s).expect("failed to parse hex");
    CanonicalDeserialize::deserialize(&buf[..]).expect("deserialize failed")
}

fn to_hex<Se: CanonicalSerialize>(data: &Se) -> String {
    let mut buf = Vec::new();
    data.serialize(&mut buf).expect("serialize failed");
    hex::encode(buf)
}

#[cfg(feature = "poseidon")]
fn get_deposit_const_params(height: usize) -> DepositConstParams<Fr, PoseidonHasher<Fr>> {
    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    DepositConstParams {
        leaf_params: setup_params_x5_4::<Fr>(curve),
        inner_params: setup_params_x5_3::<Fr>(curve),
        height,
    }
}

#[cfg(feature = "poseidon")]
fn get_withdraw_const_params(height: usize, params: &Option<RabinParameters>) -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::vanilla::rabin::RabinParam;

    #[cfg(feature = "bn254")]
    let curve = Curve::Bn254;
    #[cfg(feature = "bls12-381")]
    let curve = Curve::Bls381;

    let rabin_param = params.as_ref().map(|params| {
        let modulus = hex::decode(&params.modulus).expect("modulus is an invalid hex string");
        RabinParam::new::<Fr>(
            BigUint::from_bytes_le(&modulus),
            params.modulus_len,
            params.bit_size,
            params.cypher_batch,
        )
    });

    WithdrawConstParams {
        nullifier_params: setup_params_x5_2::<Fr>(curve),
        leaf_params: setup_params_x5_4::<Fr>(curve),
        inner_params: setup_params_x5_3::<Fr>(curve),
        height,
        rabin_param,
    }
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

struct MerkleTree {
    height: usize,
    tree: BTreeMap<(usize, u64), Fr>,
    blank: Vec<Fr>,
}

impl MerkleTree {
    fn new(height: usize, params: &PoseidonParameters<Fr>) -> Self {
        let mut nodes = Vec::with_capacity(height);
        let mut hash = PoseidonHasher::empty_hash();

        (0..height)
            .into_iter()
            .for_each(|_| {
                nodes.push(hash);
                hash = PoseidonHasher::hash_two(params, hash, hash)
                    .expect("poseidon hash error");
            });

        Self {
            height,
            tree: BTreeMap::new(),
            blank: nodes,
        }
    }

    fn get_friends(&self, index: u64) -> Vec<Fr> {
        (0..self.height)
            .into_iter()
            .map(|layer| {
                if ((index >> layer) & 1) == 1 {
                    if let Some(v) = self.tree.get(&(layer, index - 1)) {
                        *v
                    } else {
                        self.blank[layer as usize]
                    }
                } else {
                    if let Some(v) = self.tree.get(&(layer, index + 1)) {
                        *v
                    } else {
                        self.blank[layer as usize]
                    }
                }
            })
            .collect()
    }

    pub fn add_leaf(&mut self, params: &PoseidonParameters<Fr>, index: u64, mut hash: Fr) {
        (0..self.height)
            .into_iter()
            .for_each(|layer| {
                self.tree.insert((layer, index >> layer), hash);

                let friend = self.blank[layer as usize];
                if ((index >> layer) & 1) == 1 {
                    hash = PoseidonHasher::hash_two(params, friend, hash).expect("poseidon hash error");
                } else {
                    hash = PoseidonHasher::hash_two(params, hash, friend).expect("poseidon hash error");
                }
            });
    }
}

#[derive(StructOpt)]
#[structopt(name = "Maze Setup", about = "Soda Maze Setup Benchmark.")]
enum Opt {
    ProveDeposit {
        #[structopt(long, default_value = "26")]
        height: usize,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "leaf-index", default_value = "0")]
        leaf_index: u64,
        #[structopt(long, short = "m")]
        mint: Pubkey,
        #[structopt(long, short = "a")]
        amount: u64,
    },
    ProveWithdraw {
        #[structopt(long, default_value = "26")]
        height: usize,
        #[structopt(long = "rabin-path", parse(from_os_str))]
        rabin_path: Option<PathBuf>,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
        #[structopt(long)]
        seed: Option<String>,
        #[structopt(long = "index-1")]
        leaf_index_1: u64,
        #[structopt(long = "index-2")]
        leaf_index_2: u64,
        #[structopt(long)]
        mint: Pubkey,
        #[structopt(long = "deposit-amount", short = "d")]
        deposit_amount: u64,
        #[structopt(long = "withdraw-amount", short = "w")]
        withdraw_amount: u64,
    },
    VerifyDeposit {
        #[structopt(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    VerifyWithdraw {
        #[structopt(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
}

fn main() {
    let opt = Opt::from_args();

    match opt {
        Opt::ProveDeposit {
            height,
            pk_path,
            proof_path,
            seed,
            leaf_index,
            mint,
            amount,
        } => {
            let const_params = get_deposit_const_params(height);
            let friend_nodes = (0..height)
                .into_iter()
                .map(|_| Fr::rand(&mut OsRng))
                .collect::<Vec<_>>();
            let secret = Fr::rand(&mut OsRng);
            println!("secret: {}", to_hex(&secret));

            let origin_inputs = DepositOriginInputs {
                friend_nodes,
                leaf_index,
                mint: ArrayPubkey::new(mint.to_bytes()),
                amount,
                secret,
            };
            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let mut rng = get_xorshift_rng(seed);
            let (pub_in, priv_in) =
                DepositVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs).expect("generate vanilla proof failed");

            let proof = DepositInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk)
                .expect("generate snark proof failed");
            let proof_data = DepositProofData {
                height,
                mint,
                amount,
                leaf_index,
                old_root: to_hex(&pub_in.old_root),
                new_leaf: to_hex(&pub_in.new_leaf),
                update_nodes: pub_in.update_nodes.iter().map(|n| to_hex(n)).collect(),
                proof: to_hex(&proof),
            };
            write_json_to_file(&proof_path, &proof_data);
        },
        Opt::ProveWithdraw {
            height,
            pk_path,
            proof_path,
            rabin_path,
            seed,
            leaf_index_1,
            leaf_index_2,
            mint,
            deposit_amount,
            withdraw_amount,
        } => {
            let params = rabin_path.map(|path| {
                let param: RabinParameters = read_json_from_file(&path);
                param
            });
            let const_params = get_withdraw_const_params(height, &params);
            let mut merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let friend_nodes_1 = merkle_tree.blank.clone();
            
            let secret_1 = Fr::rand(&mut OsRng);
            let secret_2 = Fr::rand(&mut OsRng);
            println!("secret 1: {}", to_hex(&secret_1));
            println!("secret 2: {}", to_hex(&secret_2));

            let preimage = vec![
                ArrayPubkey::new(mint.to_bytes()).to_field_element(),
                Fr::from(deposit_amount),
                secret_1,
            ];
            let leaf = PoseidonHasher::hash(
                &const_params.leaf_params,
                &preimage[..],
            ).expect("hash failed");
            merkle_tree.add_leaf(&const_params.inner_params, leaf_index_1, leaf);

            let rabin_leaf_padding = params.map(|param| {
                let mut leaf_len = <FrParameters as FpParameters>::MODULUS_BITS as usize / param.bit_size;
                if <FrParameters as FpParameters>::MODULUS_BITS as usize % param.bit_size != 0 {
                    leaf_len += 1;
                }
                
                (0..param.modulus_len - leaf_len as usize).into_iter().map(|_| {
                    use num_bigint_dig::RandBigInt;
                    let r = OsRng.gen_biguint(param.bit_size as usize);
                    BigUint::from_bytes_le(&r.to_bytes_le())
                }).collect::<Vec<_>>()
            });

            let friend_nodes_2 = merkle_tree.get_friends(leaf_index_2);

            let origin_inputs = WithdrawOriginInputs {
                mint: ArrayPubkey::new(mint.to_bytes()),
                deposit_amount,
                withdraw_amount,
                leaf_index_1,
                leaf_index_2,
                secret_1,
                secret_2,
                friend_nodes_1,
                friend_nodes_2,
                rabin_leaf_padding,
            };
            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let (pub_in, priv_in)
                = WithdrawVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs).expect("generate vanilla proof failed");

            let mut rng = get_xorshift_rng(seed);
            let proof =
                WithdrawInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            let proof_data = WithdrawProofData {
                mint,
                withdraw_amount,
                nullifier: to_hex(&pub_in.nullifier),
                old_root: to_hex(&pub_in.old_root),
                new_leaf_index: pub_in.new_leaf_index,
                new_leaf: to_hex(&pub_in.new_leaf),
                update_nodes: pub_in.update_nodes.iter().map(|n| to_hex(n)).collect(),
                cypher: pub_in.cypher.map(|c| c.into_iter().map(|c| to_hex(&c)).collect()),
                proof: to_hex(&proof),
            };
            write_json_to_file(&proof_path, &proof_data);
        },
        Opt::VerifyDeposit {
            vk_path,
            proof_path,
        } => {
            let vk = read_from_file::<VerifyingKey<_>>(&vk_path);
            let proof_data = read_json_from_file::<DepositProofData>(&proof_path);

            let proof = from_hex(proof_data.proof);
            let pub_in = DepositPublicInputs {
                mint: ArrayPubkey::new(proof_data.mint.to_bytes()),
                amount: proof_data.amount,
                old_root: from_hex(proof_data.old_root),
                new_leaf: from_hex(proof_data.new_leaf),
                leaf_index: proof_data.leaf_index,
                update_nodes: proof_data.update_nodes.into_iter().map(|n| from_hex(n)).collect(),
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
            vk_path,
            proof_path,
        } => {
            let vk = read_from_file::<VerifyingKey<_>>(&vk_path);
            let proof_data = read_json_from_file::<WithdrawProofData>(&proof_path);

            let proof = from_hex(proof_data.proof);
            let pub_in = WithdrawPublicInputs {
                mint: ArrayPubkey::new(proof_data.mint.to_bytes()),
                withdraw_amount: proof_data.withdraw_amount,
                nullifier: from_hex(proof_data.nullifier),
                old_root: from_hex(proof_data.old_root),
                new_leaf_index: proof_data.new_leaf_index,
                new_leaf: from_hex(proof_data.new_leaf),
                update_nodes: proof_data.update_nodes.into_iter().map(|n| from_hex(n)).collect(),
                cypher: proof_data.cypher.map(|n| n.into_iter().map(|n| from_hex(n)).collect()),
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
