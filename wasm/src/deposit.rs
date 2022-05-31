use ark_std::UniformRand;
use ark_ff::{FpParameters, BigInteger256, PrimeField};
use ark_bn254::{Fr, FrParameters, Bn254};
use ark_groth16::{Groth16, Proof};
use ark_serialize::CanonicalSerialize;
use js_sys::{Uint8Array, Array};
use num_bigint::BigUint;
use rand_core::OsRng;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::pubkey::Pubkey;
use soda_maze_program::Packer;
use soda_maze_program::params::HEIGHT;
use soda_maze_program::core::node::MerkleNode;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::DepositProof};
use soda_maze_lib::vanilla::deposit::{DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::encryption::EncryptionOriginInputs;
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};

use crate::{log, Instructions, UserCredential, ProofResult};
use crate::params::{ENCRYPTION_CONST_PARAMS, DEPOSIT_CONST_PARAMS, DEFAULT_NODE_HASHES, DEPOSIT_PK};

type DepositVanillaInstant = DepositVanillaProof::<Fr, PoseidonHasher<Fr>>;
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

fn to_hex<Se: CanonicalSerialize>(data: &Se) -> String {
    let mut buf = Vec::new();
    data.serialize(&mut buf).expect("serialize failed");
    hex::encode(buf)
}

fn gen_deposit_instructions(
    vault: Pubkey,
    mint: Pubkey,
    signer: Pubkey,
    proof: Proof<Bn254>,
    pub_in: DepositPublicInputs<Fr>,
) -> Instructions {
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::verifier::Proof;
    use soda_maze_program::params::bn::{Fq, Fq2, G1Affine254, G2Affine254};
    use soda_maze_program::instruction::*;
    
    let leaf = BigInteger256::new(pub_in.leaf.into_repr().0);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        BigInteger256::new(node.into_repr().0)
    }).collect::<Vec<_>>();
    let credential = create_deposit_credential(vault, signer, pub_in.deposit_amount, leaf, Box::new(updating_nodes))
        .expect("create deposit credential failed");

    let commitment = pub_in.encryption.unwrap().cipher_field_array.into_iter().map(|c| {
        BigInteger256::new(c.into_repr().0)
    }).collect::<Vec<_>>();
    let proof = Proof {
        a: G1Affine254::new(
            Fq::new(BigInteger256::new(proof.a.x.0.0)),
            Fq::new(BigInteger256::new(proof.a.y.0.0)),
            proof.a.infinity,
        ),
        b: G2Affine254::new(
            Fq2::new(Fq::new(BigInteger256::new(proof.b.x.c0.0.0)), Fq::new(BigInteger256::new(proof.b.x.c1.0.0))),
            Fq2::new(Fq::new(BigInteger256::new(proof.b.y.c0.0.0)), Fq::new(BigInteger256::new(proof.b.y.c1.0.0))),
            proof.b.infinity,
        ),
        c: G1Affine254::new(
            Fq::new(BigInteger256::new(proof.c.x.0.0)),
            Fq::new(BigInteger256::new(proof.c.y.0.0)),
            proof.c.infinity,
        ),
    };

    let verifier = create_deposit_verifier(vault, signer, Box::new(commitment), Box::new(proof))
        .expect("create deposit verifier failed");

    let verify = (0..210).into_iter().map(|i| {
        verify_proof(vault, signer, vec![i as u8]).expect("verify proof failed")
    }).collect::<Vec<_>>();

    let finalize = finalize_deposit(vault, mint, signer, pub_in.leaf_index, leaf)
        .expect("finalize deposit failed");

    Instructions {
        credential,
        verifier,
        verify,
        finalize,
    }
}

#[wasm_bindgen]
pub fn gen_deposit_proof(
    leaf_index: u64,
    deposit_amount: u64,
    vault: Pubkey,
    signer: Pubkey,
    mint: Pubkey,
    friends: Array,
) -> JsValue {
    console_error_panic_hook::set_once();

    log("Preparing input datas...");

    let friend_nodes = friends.iter().enumerate().map(|(layer, friend)| {
        let data = Uint8Array::from(friend).to_vec();
        if data.is_empty() {
            DEFAULT_NODE_HASHES[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.unwrap_state().0)).expect("invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(friend_nodes.len(), HEIGHT, "invalid friends array length");

    let encryption = {
        let mut leaf_len = <FrParameters as FpParameters>::MODULUS_BITS as usize / ENCRYPTION_CONST_PARAMS.bit_size;
        if <FrParameters as FpParameters>::MODULUS_BITS as usize % ENCRYPTION_CONST_PARAMS.bit_size != 0 {
            leaf_len += 1;
        }
        let padding_array = (0..ENCRYPTION_CONST_PARAMS.modulus_len - leaf_len).into_iter().map(|_| {
            use num_bigint_dig::RandBigInt;
            let r = OsRng.gen_biguint(ENCRYPTION_CONST_PARAMS.bit_size);
            BigUint::from_bytes_le(&r.to_bytes_le())
        }).collect::<Vec<_>>();
        
        Some(EncryptionOriginInputs { padding_array })
    };

    let secret = Fr::rand(&mut OsRng);
    let origin_inputs = DepositOriginInputs {
        leaf_index,
        deposit_amount,
        secret,
        friend_nodes,
        encryption,
    };

    log("Generating vanilla proof...");

    let (pub_in, priv_in) =
        DepositVanillaInstant::generate_vanilla_proof(&DEPOSIT_CONST_PARAMS, &origin_inputs)
            .expect("generate vanilla proof failed");

    log("Generating snark proof...");

    let proof =
        DepositInstant::generate_snark_proof(&mut OsRng, &DEPOSIT_CONST_PARAMS, &pub_in, &priv_in, &DEPOSIT_PK)
            .expect("generate snark proof failed");

    log("Generating solana instructions...");

    let user_credential = UserCredential {
        vault,
        mint,
        balance: pub_in.deposit_amount,
        index: pub_in.leaf_index,
        secret: to_hex(&secret),
    };
    let res = ProofResult {
        user_credential,
        instructions: gen_deposit_instructions(vault, mint, signer, proof, pub_in),
    };
    JsValue::from_serde(&res).expect("serde error")
}

