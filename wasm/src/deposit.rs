use ark_ff::{FpParameters, BigInteger256, PrimeField};
use ark_bn254::{Fr, FrParameters, Bn254};
use ark_groth16::{Groth16, Proof};
use js_sys::{Uint8Array, Array};
use num_bigint::BigUint;
use rand_core::OsRng;
use wasm_bindgen::{JsValue, prelude::*};
use serde::{Serialize, Deserialize};
use solana_program::{pubkey::Pubkey, instruction::Instruction};
use soda_maze_program::{Packer, params::HEIGHT};
use soda_maze_program::core::node::MerkleNode;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::DepositProof};
use soda_maze_lib::vanilla::deposit::{DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::encryption::EncryptionOriginInputs;
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};

use crate::log;
use crate::utils::*;
use crate::params::*;

type DepositVanillaInstant = DepositVanillaProof::<Fr, PoseidonHasher<Fr>>;
type DepositInstant = DepositProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

#[derive(Serialize, Deserialize)]
struct Instructions {
    pub reset: Instruction,
    pub credential: Instruction,
    pub verifier: Instruction,
    pub verify: Vec<Instruction>,
    pub finalize: Instruction,
}

fn gen_deposit_instructions(
    vault: Pubkey,
    token_mint: Pubkey,
    depositor: Pubkey,
    proof: Proof<Bn254>,
    pub_in: DepositPublicInputs<Fr>,
    sig: &[u8],
    nonce: u64,
) -> Instructions {
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::verifier::Proof;
    use soda_maze_program::params::bn::{Fq, Fq2, G1Affine254, G2Affine254};
    use soda_maze_program::instruction::*;

    let reset = reset_deposit_buffer_accounts(vault, depositor).expect("Error: reset deposit buffer accounts failed");

    let leaf = BigInteger256::new(pub_in.leaf.into_repr().0);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        BigInteger256::new(node.into_repr().0)
    }).collect::<Vec<_>>();
    let credential = create_deposit_credential(vault, depositor, pub_in.deposit_amount, leaf, Box::new(updating_nodes))
        .expect("Error: create deposit credential failed");

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

    let verifier = create_deposit_verifier(vault, depositor, Box::new(commitment), Box::new(proof))
        .expect("Error: create deposit verifier failed");

    let verify = (0..215u8).into_iter().map(|i| {
        verify_deposit_proof(vault, depositor, vec![i]).expect("Error: verify proof failed")
    }).collect::<Vec<_>>();

    let utxo = gen_utxo_key(sig, &vault, nonce);
    let finalize = finalize_deposit(vault, token_mint, depositor, pub_in.leaf_index, leaf, utxo)
        .expect("Error: finalize deposit failed");

    Instructions {
        reset,
        credential,
        verifier,
        verify,
        finalize,
    }
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn gen_deposit_proof(
    vault: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    leaf_index: u64, // from vault info
    deposit_amount: u64,
    neighbors: Array, // get_merkle_neighbor_nodes(vault, leaf_index)
    sig: Uint8Array,
    nonce: u64,
) -> JsValue {
    console_error_panic_hook::set_once();

    log("Preparing params and datas...");

    let sig = sig.to_vec();
    assert_eq!(sig.len(), 64, "Error: sig length should be 64");
    let secret = gen_secret(&sig, &vault);

    let ref nodes_hashes = get_default_node_hashes();
    let neighbor_nodes = neighbors.iter().enumerate().map(|(layer, neighbor)| {
        let data = Uint8Array::from(neighbor).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("Error: merkle node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.hash.0)).expect("Error: invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(neighbor_nodes.len(), HEIGHT, "Error: invalid neighbors array length");

    let encryption_const_params = get_encryption_const_params();
    let encryption = {
        let mut leaf_len = <FrParameters as FpParameters>::MODULUS_BITS as usize / encryption_const_params.bit_size;
        if <FrParameters as FpParameters>::MODULUS_BITS as usize % encryption_const_params.bit_size != 0 {
            leaf_len += 1;
        }
        let padding_array = (0..encryption_const_params.modulus_len - leaf_len).into_iter().map(|_| {
            use num_bigint_dig::RandBigInt;
            let r = OsRng.gen_biguint(encryption_const_params.bit_size);
            BigUint::from_bytes_le(&r.to_bytes_le())
        }).collect::<Vec<_>>();
        
        Some(EncryptionOriginInputs { padding_array })
    };
    let deposit_const_params = get_deposit_const_params(encryption_const_params);

    let origin_inputs = DepositOriginInputs {
        leaf_index,
        deposit_amount,
        secret,
        neighbor_nodes,
        encryption,
    };

    let pk = get_deposit_pk();
    let pk = pk.into();

    log("Generating vanilla proof...");

    let (pub_in, priv_in) =
        DepositVanillaInstant::generate_vanilla_proof(&deposit_const_params, &origin_inputs)
            .expect("Error: generate vanilla proof failed");

    log("Generating snark proof...");

    let proof =
        DepositInstant::generate_snark_proof(&mut OsRng, &deposit_const_params, &pub_in, &priv_in, &pk)
            .expect("Error: generate snark proof failed");
    drop(pk);

    log("Generating solana instructions...");

    let instructions = gen_deposit_instructions(vault, mint, owner, proof, pub_in, &sig, nonce);
    JsValue::from_serde(&instructions).expect("Error: parse instructions error")
}
