use std::{collections::BTreeMap, path::PathBuf, fs::OpenOptions};
use ark_ff::{FpParameters, PrimeField};
use ark_std::{UniformRand, rand::SeedableRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Read};
use arkworks_utils::poseidon::PoseidonParameters;
use borsh::BorshDeserialize;
use clap::Parser;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{DepositProof, WithdrawProof}};
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::withdraw::{WithdrawConstParams, WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::deposit::{DepositConstParams, DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::encryption::{EncryptionConstParams, EncryptionPublicInputs, EncryptionOriginInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};
use soda_maze_types::keys::{MazeProvingKey, MazeVerifyingKey};
use soda_maze_types::params::{RabinParameters, JsonParser};
use serde::{Serialize, Deserialize};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;

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
struct DepositProofData {
    deposit_amount: u64,
    prev_root: String,
    leaf_index: u64,
    leaf: String,
    update_nodes: Vec<String>,
    cipher_array: Option<Vec<String>>,
    proof: String,
}

impl JsonParser for DepositProofData {}

#[derive(Serialize, Deserialize)]
struct WithdrawProofData {
    withdraw_amount: u64,
    receiver: String,
    nullifier: String,
    prev_root: String,
    dst_leaf_index: u64,
    dst_leaf: String,
    update_nodes: Vec<String>,
    proof: String,
}

impl JsonParser for WithdrawProofData {}

fn read_from_file<De: BorshDeserialize>(path: &PathBuf) -> De {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("read from file error");
    BorshDeserialize::deserialize(&mut &buffer[..]).expect("failed to parse file")
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

struct MerkleTree<'a> {
    params: &'a PoseidonParameters<Fr>,
    height: usize,
    tree: BTreeMap<(usize, u64), Fr>,
    blank: Vec<Fr>,
}

impl<'a> MerkleTree<'a> {
    fn new(height: usize, params: &'a PoseidonParameters<Fr>) -> Self {
        let mut nodes = Vec::with_capacity(height);
        let mut hash: Fr = PoseidonHasher::empty_hash();

        (0..height)
            .into_iter()
            .for_each(|_| {
                nodes.push(hash);
                hash = PoseidonHasher::hash_two(params, hash, hash)
                    .expect("poseidon hash error");
            });

        let hash = hash.into_repr();
        println!("Merkle Root: BigInteger::new({:?})", &hash.0);

        Self {
            params,
            height,
            tree: BTreeMap::new(),
            blank: nodes,
        }
    }

    fn get_neighbors(&self, index: u64) -> Vec<Fr> {
        (0..self.height)
            .into_iter()
            .map(|layer| {
                let index = index >> layer;
                let neighbor = if (index & 1) == 1 {
                    self.tree.get(&(layer, index - 1)).unwrap_or_else(|| &self.blank[layer])
                } else {
                    self.tree.get(&(layer, index + 1)).unwrap_or_else(|| &self.blank[layer])
                };

                *neighbor
            })
            .collect()
    }

    pub fn add_leaf(&mut self, index: u64, mut hash: Fr) {
        (0..self.height)
            .into_iter()
            .for_each(|layer| {
                let index = index >> layer;
                self.tree.insert((layer, index), hash);

                if (index & 1) == 1 {
                    let neighbor = self.tree.get(&(layer, index - 1)).unwrap_or_else(|| &self.blank[layer]);
                    hash = PoseidonHasher::hash_two(self.params, *neighbor, hash).expect("poseidon hash error");
                } else {
                    let neighbor = self.tree.get(&(layer, index + 1)).unwrap_or_else(|| &self.blank[layer]);
                    hash = PoseidonHasher::hash_two(self.params, hash, *neighbor).expect("poseidon hash error");
                }
            });
    }
}

#[derive(Parser, Debug)]
#[clap(name = "Soda Maze Setup", version = "0.0.1", about = "Soda Maze Setup Benchmark.", long_about = "")]
enum Opt {
    ProveDeposit {
        #[clap(long, short = 's', value_parser)]
        seed: Option<String>,
        #[clap(long, value_parser, default_value = "21")]
        height: usize,
        #[clap(long = "deposit-amount", value_parser, default_value = "1")]
        deposit_amount: u64,
        #[clap(long = "leaf-index", value_parser, default_value = "0")]
        leaf_index: u64,
        #[clap(long = "rabin-path", parse(from_os_str))]
        rabin_path: Option<PathBuf>,
        #[clap(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    ProveWithdraw {
        #[clap(long, short = 's', value_parser)]
        seed: Option<String>,
        #[clap(long, value_parser, default_value = "21")]
        height: usize,
        #[clap(long = "balance", value_parser, default_value = "1")]
        balance: u64,
        #[clap(long = "withdraw-amount", value_parser, default_value = "1")]
        withdraw_amount: u64,
        #[clap(long = "src-index", value_parser, default_value = "0")]
        src_index: u64,
        #[clap(long = "dst-index", value_parser, default_value = "1")]
        dst_index: u64,
        #[clap(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    VerifyDeposit {
        #[clap(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    VerifyWithdraw {
        #[clap(long = "vk-path", parse(from_os_str))]
        vk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    }
}

fn main() {
    let opt = Opt::parse();

    match opt {
        Opt::ProveDeposit {
            seed,
            height,
            deposit_amount,
            leaf_index,
            rabin_path,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let const_params = rabin_path.as_ref().map(|rabin_path| {
                let params = RabinParameters::from_file(&rabin_path).expect("read rabin params from file error");
                get_encryption_const_params(params)
            });
            let const_params = get_deposit_const_params(
                height,
                const_params,
            );

            let rabin_orig_in = rabin_path.map(|rabin_path| {
                let params = RabinParameters::from_file(&rabin_path).expect("read rabin params from file error");
                let mut leaf_len = <FrParameters as FpParameters>::MODULUS_BITS as usize / params.bit_size;
                if <FrParameters as FpParameters>::MODULUS_BITS as usize % params.bit_size != 0 {
                    leaf_len += 1;
                }
                
                let padding_array = (0..params.modulus_len - leaf_len).into_iter().map(|_| {
                    use num_bigint_dig::RandBigInt;
                    let r = OsRng.gen_biguint(params.bit_size);
                    BigUint::from_bytes_le(&r.to_bytes_le())
                }).collect::<Vec<_>>();

                EncryptionOriginInputs { padding_array }
            });
            
            let secret = Fr::rand(&mut OsRng);
            let merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let neighbor_nodes = merkle_tree.blank.clone();

            let origin_inputs = DepositOriginInputs {
                leaf_index,
                deposit_amount,
                secret,
                neighbor_nodes,
                encryption: rabin_orig_in,
            };
            
            let pk = read_from_file::<MazeProvingKey>(&pk_path);
            let pk = pk.into();
            let (pub_in, priv_in) =
                DepositVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
                    .expect("generate vanilla proof failed");

            let mut rng = get_xorshift_rng(seed);
            let proof =
                DepositInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            let cipher_array = pub_in.encryption
                .map(|e| {
                    e.cipher_field_array.iter().map(|c| to_hex(c)).collect::<Vec<_>>()
                });
            let proof_data = DepositProofData {
                deposit_amount,
                prev_root: to_hex(&pub_in.prev_root),
                leaf: to_hex(&pub_in.leaf),
                leaf_index: pub_in.leaf_index,
                update_nodes: pub_in.update_nodes.iter().map(|n| to_hex(n)).collect(),
                cipher_array,
                proof: to_hex(&proof),
            };
            proof_data.to_file(&proof_path).expect("write proof data to file error");

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        }
        Opt::ProveWithdraw {
            seed,
            height,
            balance,
            withdraw_amount,
            src_index,
            dst_index,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let const_params = get_withdraw_const_params(height);
            let mut merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let receiver = Fr::rand(&mut OsRng);
            let secret = Fr::rand(&mut OsRng);
            let src_leaf = PoseidonHasher::hash(
                &const_params.leaf_params,
                &[Fr::from(src_index), Fr::from(balance), secret],
            ).expect("hash failed");
            merkle_tree.add_leaf(src_index, src_leaf);
            let src_neighbor_nodes = merkle_tree.get_neighbors(src_index);
            let dst_neighbor_nodes = merkle_tree.get_neighbors(dst_index);

            let origin_inputs = WithdrawOriginInputs {
                balance,
                withdraw_amount,
                src_leaf_index: src_index,
                dst_leaf_index: dst_index,
                receiver,
                secret,
                src_neighbor_nodes,
                dst_neighbor_nodes,
            };

            let pk = read_from_file::<MazeProvingKey>(&pk_path);
            let pk = pk.into();
            let (pub_in, priv_in)
                = WithdrawVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs).expect("generate vanilla proof failed");

            let mut rng = get_xorshift_rng(seed);
            let proof =
                WithdrawInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            let proof_data = WithdrawProofData {
                withdraw_amount: pub_in.withdraw_amount,
                receiver: to_hex(&pub_in.receiver), 
                nullifier: to_hex(&pub_in.nullifier),
                prev_root: to_hex(&pub_in.prev_root),
                dst_leaf_index: pub_in.dst_leaf_index,
                dst_leaf: to_hex(&pub_in.dst_leaf),
                update_nodes: pub_in.update_nodes.iter().map(|n| to_hex(n)).collect(),
                proof: to_hex(&proof),
            };
            proof_data.to_file(&proof_path).expect("write proof data to file error");

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        },
        Opt::VerifyDeposit {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = read_from_file::<MazeVerifyingKey>(&vk_path);
            let vk = vk.into();
            let proof_data = DepositProofData::from_file(&proof_path).expect("read proof data from file error");

            let proof = from_hex(proof_data.proof);
            let cipher_field_array = proof_data.cipher_array
                .map(|c| {
                    c.into_iter().map(|s| from_hex(s)).collect::<Vec<_>>()
                });
            let encryption = cipher_field_array.map(|c| {
                EncryptionPublicInputs { cipher_field_array: c }
            });
            let pub_in = DepositPublicInputs {
                leaf_index: proof_data.leaf_index,
                deposit_amount: proof_data.deposit_amount,
                leaf: from_hex(proof_data.leaf),
                prev_root: from_hex(proof_data.prev_root),
                update_nodes: proof_data.update_nodes.into_iter().map(|n| from_hex(n)).collect(),
                encryption,
            };

            let result = DepositInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify deposit proof success");
            } else {
                println!("verify deposit proof failed");
            }

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);

            // println!("proof a");
            // println!("-----------------------------------------------------");
            // println!("G1Affine254::new_const(");
            // println!("    Fq::new(BigInteger::new({:?})),", proof.a.x.0.0);
            // println!("    Fq::new(BigInteger::new({:?})),", proof.a.y.0.0);
            // println!("    {}", proof.a.infinity);
            // println!(")");
            // println!("-----------------------------------------------------");

            // println!("proof b");
            // println!("-----------------------------------------------------");
            // println!("G2Affine254::new_const(");
            // println!("    Fq2::new_const(");
            // println!("        Fq::new(BigInteger::new({:?})),", proof.b.x.c0.0.0);
            // println!("        Fq::new(BigInteger::new({:?})),", proof.b.x.c1.0.0);
            // println!("    ),");
            // println!("    Fq2::new_const(");
            // println!("        Fq::new(BigInteger::new({:?})),", proof.b.y.c0.0.0);
            // println!("        Fq::new(BigInteger::new({:?})),", proof.b.y.c1.0.0);
            // println!("    ),");
            // println!("    {}", proof.b.infinity);
            // println!(")");
            // println!("-----------------------------------------------------");

            // println!("proof c");
            // println!("-----------------------------------------------------");
            // println!("G1Affine254::new_const(");
            // println!("    Fq::new(BigInteger::new({:?})),", proof.c.x.0.0);
            // println!("    Fq::new(BigInteger::new({:?})),", proof.c.y.0.0);
            // println!("    {}", proof.c.infinity);
            // println!(")");
            // println!("-----------------------------------------------------");

            // println!("leaf");
            // println!("-----------------------------------------------------");
            // println!("BigInteger::new({:?})", pub_in.leaf.into_repr().0);
            // println!("-----------------------------------------------------");

            // println!("prev_root");
            // println!("-----------------------------------------------------");
            // println!("BigInteger::new({:?})", pub_in.prev_root.into_repr().0);
            // println!("-----------------------------------------------------");

            // println!("update_nodes");
            // println!("-----------------------------------------------------");
            // println!("[");
            // pub_in.update_nodes.iter().for_each(|p| {
            //     println!("    BigInteger::new({:?})", p.into_repr().0);
            // });
            // println!("]");
            // println!("-----------------------------------------------------");

            // println!("encryption");
            // println!("-----------------------------------------------------");
            // println!("[");
            // pub_in.encryption.as_ref().unwrap().cipher_field_array.iter().for_each(|p| {
            //     println!("    BigInteger::new({:?})", p.into_repr().0);
            // });
            // println!("]");
            // println!("-----------------------------------------------------");
        },
        Opt::VerifyWithdraw {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = read_from_file::<MazeVerifyingKey>(&vk_path);
            let vk = vk.into();
            let proof_data = WithdrawProofData::from_file(&proof_path).expect("read proof data from file error");

            let proof = from_hex(proof_data.proof);
            let pub_in = WithdrawPublicInputs {
                withdraw_amount: proof_data.withdraw_amount,
                receiver: from_hex(proof_data.receiver),
                nullifier: from_hex(proof_data.nullifier),
                prev_root: from_hex(proof_data.prev_root),
                dst_leaf_index: proof_data.dst_leaf_index,
                dst_leaf: from_hex(proof_data.dst_leaf),
                update_nodes: proof_data.update_nodes.into_iter().map(|n| from_hex(n)).collect(),
            };

            let result = WithdrawInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify withdraw proof success");
            } else {
                println!("verify withdraw proof failed");
            }

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        },
    }
}
