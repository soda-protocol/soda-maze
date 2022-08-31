use ark_std::{collections::BTreeMap, path::PathBuf, UniformRand};
use ark_ec::models::twisted_edwards_extended::GroupAffine;
use ark_groth16::Groth16;
use clap::Parser;
use soda_maze_lib::proof::{scheme::{DepositProof, WithdrawProof}, ProofScheme};
use soda_maze_lib::vanilla::{hasher::FieldHasher, VanillaProof};
use soda_maze_lib::vanilla::withdraw::{WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::deposit::{DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::commit::{CommitOriginInputs, CommitPublicInputs};
use soda_maze_types::{keys::{MazeProvingKey, MazeVerifyingKey}, parser::to_hex_string};
use soda_maze_types::params::{gen_deposit_const_params, gen_withdraw_const_params};
use soda_maze_types::parser::{JsonParser, from_hex_string, borsh_de_from_file};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
#[cfg(feature = "poseidon")]
use arkworks_utils::poseidon::PoseidonParameters;
#[cfg(feature = "poseidon")]
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
#[cfg(feature = "poseidon")]
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;


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

#[cfg(feature = "poseidon")]
type DepositVanillaInstant = DepositVanillaProof::<EdwardsParameters, PoseidonHasher<Fr>>;

#[cfg(feature = "poseidon")]
type WithdrawVanillaInstant = WithdrawVanillaProof::<EdwardsParameters, PoseidonHasher<Fr>>;

#[derive(Serialize, Deserialize)]
struct DepositProofData {
    deposit_amount: u64,
    prev_root: String,
    leaf_index: u64,
    leaf: String,
    update_nodes: Vec<String>,
    commitment: Option<String>,
    proof: String,
}

impl JsonParser for DepositProofData {}

#[derive(Serialize, Deserialize)]
struct WithdrawProofData {
    withdraw_amount: u64,
    receiver: String,
    nullifier_point: String,
    prev_root: String,
    dst_leaf_index: u64,
    dst_leaf: String,
    update_nodes: Vec<String>,
    commitment: Option<String>,
    proof: String,
}

impl JsonParser for WithdrawProofData {}

#[cfg(feature = "poseidon")]
struct MerkleTree<'a> {
    params: &'a PoseidonParameters<Fr>,
    height: usize,
    tree: BTreeMap<(usize, u64), Fr>,
    blank: Vec<Fr>,
}

#[cfg(feature = "poseidon")]
impl<'a> MerkleTree<'a> {
    fn new(height: usize, params: &'a PoseidonParameters<Fr>) -> Self {
        let mut nodes = Vec::with_capacity(height);
        let mut hash: Fr = PoseidonHasher::empty_hash();

        (0..height)
            .into_iter()
            .for_each(|_| {
                nodes.push(hash);
                hash = PoseidonHasher::hash_two(params, hash, hash).unwrap();
            });

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
        #[clap(long, value_parser, default_value = "21")]
        height: usize,
        #[clap(long = "deposit-amount", value_parser, default_value = "1")]
        deposit_amount: u64,
        #[clap(long = "leaf-index", value_parser, default_value = "0")]
        leaf_index: u64,
        #[clap(long = "viewing-pubkey", value_parser)]
        pubkey: Option<String>,
        #[clap(long = "pk-path", parse(from_os_str), default_value = "pk-deposit")]
        pk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str), default_value = "proof.json")]
        proof_path: PathBuf,
    },
    ProveWithdraw {
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
        #[clap(long = "viewing-pubkey", value_parser)]
        pubkey: Option<String>,
        #[clap(long = "pk-path", parse(from_os_str), default_value = "pk-withdraw")]
        pk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str), default_value = "proof.json")]
        proof_path: PathBuf,
    },
    VerifyDeposit {
        #[clap(long = "vk-path", parse(from_os_str), default_value = "vk-deposit")]
        vk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str), default_value = "proof.json")]
        proof_path: PathBuf,
    },
    VerifyWithdraw {
        #[clap(long = "vk-path", parse(from_os_str), default_value = "vk-withdraw")]
        vk_path: PathBuf,
        #[clap(long = "proof-path", parse(from_os_str), default_value = "proof.json")]
        proof_path: PathBuf,
    }
}

fn main() {
    let opt = Opt::parse();

    match opt {
        Opt::ProveDeposit {
            height,
            deposit_amount,
            leaf_index,
            pubkey,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();
            let rng = &mut OsRng;

            let pubkey = pubkey.map(|pubkey| {
                from_hex_string::<GroupAffine<EdwardsParameters>>(pubkey).expect("invalid viewing pubkey")
            });
            let const_params = gen_deposit_const_params(
                height,
                pubkey,
            );
            
            let secret = Fr::rand(rng);
            let merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let neighbor_nodes = merkle_tree.blank.clone();

            let origin_inputs = DepositOriginInputs {
                leaf_index,
                deposit_amount,
                secret,
                neighbor_nodes,
                commit: pubkey.and(Some(CommitOriginInputs { nonce: Frr::rand(rng) })),
            };

            let pk = borsh_de_from_file::<MazeProvingKey>(&pk_path).expect("invalid proving key file");
            let pk = pk.into();
            let (pub_in, priv_in) =
                DepositVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
                    .expect("generate vanilla proof failed");
            let proof =
                DepositInstant::generate_snark_proof(rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");

            let proof_data = DepositProofData {
                deposit_amount,
                prev_root: to_hex_string(&pub_in.prev_root).unwrap(),
                leaf: to_hex_string(&pub_in.leaf).unwrap(),
                leaf_index: pub_in.leaf_index,
                update_nodes: pub_in.update_nodes.iter().map(|n| {
                    to_hex_string(n).unwrap()
                }).collect(),
                commitment: pub_in.commit.as_ref().map(|commit| {
                    to_hex_string(&commit.commitment).unwrap()
                }),
                proof: to_hex_string(&proof).unwrap(),
            };
            proof_data.to_file(&proof_path).expect("write proof data to file error");

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("prove time: {:?}", duration);
        }
        Opt::ProveWithdraw {
            height,
            balance,
            withdraw_amount,
            src_index,
            dst_index,
            pubkey,
            pk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();
            let rng = &mut OsRng;

            let pubkey = pubkey.map(|pubkey| {
                from_hex_string::<GroupAffine<EdwardsParameters>>(pubkey).expect("invalid viewing pubkey")
            });
            let const_params = gen_withdraw_const_params(
                height,
                pubkey,
            );

            let mut merkle_tree = MerkleTree::new(height, &const_params.inner_params);
            let receiver = Fr::rand(rng);
            let secret = Fr::rand(rng);
            let src_leaf = PoseidonHasher::hash(
                &const_params.leaf_params,
                &[Fr::from(src_index), Fr::from(balance), secret],
            ).unwrap();
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
                commit: pubkey.and(Some(CommitOriginInputs { nonce: Frr::rand(rng) })),
            };

            let pk = borsh_de_from_file::<MazeProvingKey>(&pk_path).expect("invalid proving key file");
            let pk = pk.into();
            let (pub_in, priv_in)
                = WithdrawVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs).expect("generate vanilla proof failed");
            let proof =
                WithdrawInstant::generate_snark_proof(rng, &const_params, &pub_in, &priv_in, &pk).expect("generate snark proof failed");
            
            let proof_data = WithdrawProofData {
                withdraw_amount: pub_in.withdraw_amount,
                receiver: to_hex_string(&pub_in.receiver).unwrap(), 
                prev_root: to_hex_string(&pub_in.prev_root).unwrap(),
                dst_leaf_index: pub_in.dst_leaf_index,
                dst_leaf: to_hex_string(&pub_in.dst_leaf).unwrap(),
                nullifier_point: to_hex_string(&pub_in.nullifier_point).unwrap(),
                update_nodes: pub_in.update_nodes.iter().map(|n| {
                    to_hex_string(n).unwrap()
                }).collect(),
                commitment: pub_in.commit.as_ref().map(|commit| {
                    to_hex_string(&commit.commitment).unwrap()
                }),
                proof: to_hex_string(&proof).unwrap(),
            };
            proof_data.to_file(&proof_path).expect("write proof data to file error");

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("prove time: {:?}", duration);
        },
        Opt::VerifyDeposit {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = borsh_de_from_file::<MazeVerifyingKey>(&vk_path).expect("invalid verifying key file");
            let vk = vk.into();
            let proof_data = DepositProofData::from_file(&proof_path).expect("read proof data from file error");

            let pub_in = DepositPublicInputs {
                leaf_index: proof_data.leaf_index,
                deposit_amount: proof_data.deposit_amount,
                leaf: from_hex_string(proof_data.leaf).expect("invalid leaf string"),
                prev_root: from_hex_string(proof_data.prev_root).expect("invalid prev root string"),
                update_nodes: proof_data.update_nodes.into_iter().map(|n| {
                    from_hex_string(n).expect("invalid node string")
                }).collect(),
                commit: proof_data.commitment.map(|commitment| {
                    CommitPublicInputs {
                        commitment: from_hex_string(commitment).expect("invalid commitment string"),
                    }
                }),
            };
            let proof = from_hex_string(proof_data.proof).expect("invalid proof string");

            let result = DepositInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify proof passed");
            } else {
                println!("verify proof failed");
            }

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("verify time: {:?}", duration);

            use ark_ff::PrimeField;
            println!("proof a");
            println!("-----------------------------------------------------");
            println!("G1Affine254::new_const(");
            println!("    Fq::new(BigInteger::new({:?})),", proof.a.x.0.0);
            println!("    Fq::new(BigInteger::new({:?})),", proof.a.y.0.0);
            println!("    {}", proof.a.infinity);
            println!(")");
            println!("-----------------------------------------------------");

            println!("proof b");
            println!("-----------------------------------------------------");
            println!("G2Affine254::new_const(");
            println!("    Fq2::new_const(");
            println!("        Fq::new(BigInteger::new({:?})),", proof.b.x.c0.0.0);
            println!("        Fq::new(BigInteger::new({:?})),", proof.b.x.c1.0.0);
            println!("    ),");
            println!("    Fq2::new_const(");
            println!("        Fq::new(BigInteger::new({:?})),", proof.b.y.c0.0.0);
            println!("        Fq::new(BigInteger::new({:?})),", proof.b.y.c1.0.0);
            println!("    ),");
            println!("    {}", proof.b.infinity);
            println!(")");
            println!("-----------------------------------------------------");

            println!("proof c");
            println!("-----------------------------------------------------");
            println!("G1Affine254::new_const(");
            println!("    Fq::new(BigInteger::new({:?})),", proof.c.x.0.0);
            println!("    Fq::new(BigInteger::new({:?})),", proof.c.y.0.0);
            println!("    {}", proof.c.infinity);
            println!(")");
            println!("-----------------------------------------------------");

            println!("leaf");
            println!("-----------------------------------------------------");
            println!("BigInteger::new({:?})", pub_in.leaf.into_repr().0);
            println!("-----------------------------------------------------");

            println!("prev_root");
            println!("-----------------------------------------------------");
            println!("BigInteger::new({:?})", pub_in.prev_root.into_repr().0);
            println!("-----------------------------------------------------");

            println!("update_nodes");
            println!("-----------------------------------------------------");
            println!("[");
            pub_in.update_nodes.iter().for_each(|p| {
                println!("    BigInteger::new({:?})", p.into_repr().0);
            });
            println!("]");
            println!("-----------------------------------------------------");

            println!("commitment");
            println!("-----------------------------------------------------");
            let commitment = pub_in.commit.as_ref().unwrap().commitment;
            println!("BigInteger::new({:?})", commitment.0.x.into_repr().0);
            println!("BigInteger::new({:?})", commitment.0.y.into_repr().0);
            println!("BigInteger::new({:?})", commitment.1.x.into_repr().0);
            println!("BigInteger::new({:?})", commitment.1.y.into_repr().0);
            println!("-----------------------------------------------------");
        },
        Opt::VerifyWithdraw {
            vk_path,
            proof_path,
        } => {
            let start_time = std::time::SystemTime::now();

            let vk = borsh_de_from_file::<MazeVerifyingKey>(&vk_path).expect("invalid verifying key file");
            let vk = vk.into();
            let proof_data = WithdrawProofData::from_file(&proof_path).expect("read proof data from file error");

            let pub_in = WithdrawPublicInputs {
                withdraw_amount: proof_data.withdraw_amount,
                receiver: from_hex_string(proof_data.receiver).expect("invalid receiver string"),
                prev_root: from_hex_string(proof_data.prev_root).expect("invalid prev root string"),
                dst_leaf_index: proof_data.dst_leaf_index,
                dst_leaf: from_hex_string(proof_data.dst_leaf).expect("invalid dst leaf string"),
                nullifier_point: from_hex_string(proof_data.nullifier_point).expect("invalid nullifier string"),
                update_nodes: proof_data.update_nodes.into_iter().map(|n| {
                    from_hex_string(n).expect("invalid node string")
                }).collect(),
                commit: proof_data.commitment.map(|commitment| {
                    CommitPublicInputs {
                        commitment: from_hex_string(commitment).expect("invalid commitment string"),
                    }
                }),
            };
            let proof = from_hex_string(proof_data.proof).expect("invalid proof string");

            let result = WithdrawInstant::verify_snark_proof(&pub_in, &proof, &vk)
                .expect("verify snark proof failed");
            if result {
                println!("verify proof passed");
            } else {
                println!("verify proof failed");
            }

            let duration = std::time::SystemTime::now().duration_since(start_time).unwrap();
            println!("verify time: {:?}", duration);
        },
    }
}
