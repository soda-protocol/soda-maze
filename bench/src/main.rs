use std::collections::BTreeMap;
use std::{path::PathBuf, fs::OpenOptions};
use ark_ff::FpParameters;
use ark_std::{UniformRand, rand::SeedableRng};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use arkworks_utils::poseidon::PoseidonParameters;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::{EncryptionProof, WithdrawProof}};
use soda_maze_lib::vanilla::hasher::FieldHasher;
use soda_maze_lib::vanilla::withdraw::{WithdrawConstParams, WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::encryption::{EncryptionConstParams, EncryptionVanillaProof, EncryptionOriginInputs, EncryptionPublicInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};
use structopt::StructOpt;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore, OsRng};
use rand_xorshift::XorShiftRng;
use serde::{Serialize, Deserialize, de::DeserializeOwned};

#[cfg(feature = "bn254")]
use ark_bn254::{Bn254, Fr, FrParameters};
#[cfg(feature = "bls12-381")]
use ark_bls12_381::{Bls12_381, Fr, FrParameters};
#[cfg(feature = "groth16")]
use ark_groth16::Groth16;

#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type EncryptionInstant = EncryptionProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type EncryptionInstant = EncryptionProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

#[cfg(all(feature = "bn254", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;
#[cfg(all(feature = "bls12-381", feature = "poseidon", feature = "groth16"))]
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bls12_381>>;

#[cfg(all(feature = "poseidon"))]
type EncryptionVanillaInstant = EncryptionVanillaProof::<Fr, PoseidonHasher<Fr>>;

#[cfg(all(feature = "poseidon"))]
type WithdrawVanillaInstant = WithdrawVanillaProof::<Fr, PoseidonHasher<Fr>>;

#[derive(Serialize, Deserialize)]
struct RabinParameters {
    modulus: String,
    modulus_len: usize,
    bit_size: usize,
    cipher_batch: usize,
}

#[derive(Serialize, Deserialize)]
struct EncryptionProofData {
    leaf_index: u64,
    commitment: String,
    cipher_array: Vec<String>,
    proof: String,
}

#[derive(Serialize, Deserialize)]
struct WithdrawProofData {
    withdraw_amount: u64,
    nullifier: String,
    old_root: String,
    new_leaf_index: u64,
    new_leaf: String,
    update_nodes: Vec<String>,
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

#[cfg(all(feature = "poseidon", feature = "bn254"))]
fn get_encryption_const_params(params: RabinParameters) -> EncryptionConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::{params::poseidon::*, vanilla::biguint::biguint_to_biguint_array};

    let modulus = hex::decode(params.modulus).expect("modulus is an invalid hex string");
    let modulus = BigUint::from_bytes_le(&modulus);
    let modulus_array = biguint_to_biguint_array(modulus, params.modulus_len, params.bit_size);

    EncryptionConstParams {
        commitment_params: get_poseidon_bn254_for_commitment(),
        nullifier_params: get_poseidon_bn254_for_nullifier(),
        modulus_array,
        modulus_len: params.modulus_len,
        bit_size: params.bit_size,
        cipher_batch: params.cipher_batch,
    }
}

#[cfg(all(feature = "poseidon", feature = "bn254"))]
fn get_withdraw_const_params(height: usize) -> WithdrawConstParams<Fr, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;
    
    WithdrawConstParams {
        commitment_params: get_poseidon_bn254_for_commitment(),
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

struct MerkleTree {
    height: usize,
    tree: BTreeMap<(usize, u64), Fr>,
    blank: Vec<Fr>,
}

impl MerkleTree {
    fn new(height: usize, params: &PoseidonParameters<Fr>) -> Self {
        let mut nodes = Vec::with_capacity(height);
        let mut hash: Fr = PoseidonHasher::empty_hash();

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
    ProveEncryption {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long = "rabin-path", parse(from_os_str))]
        rabin_path: PathBuf,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    ProveWithdraw {
        #[structopt(long, short = "s")]
        seed: Option<String>,
        #[structopt(long, default_value = "27")]
        height: usize,
        #[structopt(long = "pk-path", parse(from_os_str))]
        pk_path: PathBuf,
        #[structopt(long = "proof-path", parse(from_os_str))]
        proof_path: PathBuf,
    },
    VerifyEncryption {
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
    }
}

fn main() {
    let opt = Opt::from_args();

    match opt {
        Opt::ProveEncryption {
            seed,
            rabin_path,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let params: RabinParameters = read_json_from_file(&rabin_path);
            let const_params = get_encryption_const_params(params);
            
            let leaf_index = u64::rand(&mut OsRng);
            let secret = Fr::rand(&mut OsRng);
            let padding_array = {
                let mut leaf_len = <FrParameters as FpParameters>::MODULUS_BITS as usize / const_params.bit_size;
                if <FrParameters as FpParameters>::MODULUS_BITS as usize % const_params.bit_size != 0 {
                    leaf_len += 1;
                }
                
                (0..const_params.modulus_len - leaf_len).into_iter().map(|_| {
                    use num_bigint_dig::RandBigInt;
                    let r = OsRng.gen_biguint(const_params.bit_size);
                    BigUint::from_bytes_le(&r.to_bytes_le())
                }).collect::<Vec<_>>()
            };

            let origin_inputs = EncryptionOriginInputs {
                leaf_index,
                secret,
                padding_array,
            };
            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let (pub_in, priv_in)
                = EncryptionVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
                    .expect("generate vanilla proof failed");

            let mut rng = get_xorshift_rng(seed);
            let proof =
                EncryptionInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            let proof_data = EncryptionProofData {
                leaf_index: pub_in.leaf_index,
                commitment: to_hex(&pub_in.commitment),
                cipher_array: pub_in.cipher_field_array.iter().map(|c| to_hex(c)).collect(),
                proof: to_hex(&proof),
            };
            write_json_to_file(&proof_path, &proof_data);

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        }
        Opt::ProveWithdraw {
            seed,
            height,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let const_params = get_withdraw_const_params(height);
            let mut merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let friend_nodes_1 = merkle_tree.blank.clone();

            // const_params.commitment_params.round_keys.iter().for_each(|k| {
            //     println!("    Fr::new(BigInteger::new({:?})),", &k.0.0);
            // });
            // const_params.commitment_params.mds_matrix.iter().for_each(|ks| {
            //     println!("    &[");
            //     ks.iter().for_each(|k| {
            //         println!("        Fr::new(BigInteger::new({:?})),", &k.0.0);
            //     });
            //     println!("    ],");
            // });

            // println!("--------------------------------------------------------------------");
            // const_params.nullifier_params.round_keys.iter().for_each(|k| {
            //     println!("    Fr::new(BigInteger::new({:?})),", &k.0.0);
            // });
            // const_params.nullifier_params.mds_matrix.iter().for_each(|ks| {
            //     println!("    &[");
            //     ks.iter().for_each(|k| {
            //         println!("        Fr::new(BigInteger::new({:?})),", &k.0.0);
            //     });
            //     println!("    ],");
            // });

            // println!("--------------------------------------------------------------------");
            // const_params.leaf_params.round_keys.iter().for_each(|k| {
            //     println!("    Fr::new(BigInteger::new({:?})),", &k.0.0);
            // });
            // const_params.leaf_params.mds_matrix.iter().for_each(|ks| {
            //     println!("    &[");
            //     ks.iter().for_each(|k| {
            //         println!("        Fr::new(BigInteger::new({:?})),", &k.0.0);
            //     });
            //     println!("    ],");
            // });

            println!("--------------------------------------------------------------------");
            const_params.inner_params.round_keys.iter().for_each(|k| {
                println!("    Fr::new(BigInteger::new({:?})),", &k.0.0);
            });
            const_params.inner_params.mds_matrix.iter().for_each(|ks| {
                println!("    &[");
                ks.iter().for_each(|k| {
                    println!("        Fr::new(BigInteger::new({:?})),", &k.0.0);
                });
                println!("    ],");
            });

            let amount_1 = u64::rand(&mut OsRng);
            let amount_2 = u64::rand(&mut OsRng);
            let deposit_amount = amount_1.max(amount_2);
            let withdraw_amount = amount_1.min(amount_2);
            let secret_1 = Fr::rand(&mut OsRng);
            let secret_2 = Fr::rand(&mut OsRng);
            let commitment = PoseidonHasher::hash(
                &const_params.commitment_params,
                &[secret_1],
            ).expect("hash failed");
            let leaf = PoseidonHasher::hash(
                &const_params.leaf_params,
                &[Fr::from(deposit_amount), commitment],
            ).expect("hash failed");
            merkle_tree.add_leaf(&const_params.inner_params, 0, leaf);
            let friend_nodes_2 = merkle_tree.get_friends(1);

            let origin_inputs = WithdrawOriginInputs {
                deposit_amount,
                withdraw_amount,
                leaf_index_1: 0,
                leaf_index_2: 1,
                secret_1,
                secret_2,
                friend_nodes_1,
                friend_nodes_2,
            };
            let pk = read_from_file::<ProvingKey<_>>(&pk_path);
            let (pub_in, priv_in)
                = WithdrawVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs).expect("generate vanilla proof failed");

            let mut rng = get_xorshift_rng(seed);
            let proof =
                WithdrawInstant::generate_snark_proof(&mut rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            let proof_data = WithdrawProofData {
                withdraw_amount: pub_in.withdraw_amount,
                nullifier: to_hex(&pub_in.nullifier),
                old_root: to_hex(&pub_in.old_root),
                new_leaf_index: pub_in.new_leaf_index,
                new_leaf: to_hex(&pub_in.new_leaf),
                update_nodes: pub_in.update_nodes.iter().map(|n| to_hex(n)).collect(),
                proof: to_hex(&proof),
            };
            write_json_to_file(&proof_path, &proof_data);

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        },
        Opt::VerifyEncryption {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = read_from_file::<VerifyingKey<_>>(&vk_path);
            let proof_data = read_json_from_file::<EncryptionProofData>(&proof_path);

            let proof = from_hex(proof_data.proof);
            let pub_in = EncryptionPublicInputs {
                leaf_index: proof_data.leaf_index,
                commitment: from_hex(proof_data.commitment),
                cipher_field_array: proof_data.cipher_array.iter().map(|c| from_hex(c.clone())).collect(),
            };

            let result = EncryptionInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify encryption proof success");
            } else {
                println!("verify encryption proof failed");
            }

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("proof time: {:?}", duration);
        },
        Opt::VerifyWithdraw {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = read_from_file::<VerifyingKey<_>>(&vk_path);
            let proof_data = read_json_from_file::<WithdrawProofData>(&proof_path);

            let proof = from_hex(proof_data.proof);
            let pub_in = WithdrawPublicInputs {
                withdraw_amount: proof_data.withdraw_amount,
                nullifier: from_hex(proof_data.nullifier),
                old_root: from_hex(proof_data.old_root),
                new_leaf_index: proof_data.new_leaf_index,
                new_leaf: from_hex(proof_data.new_leaf),
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
