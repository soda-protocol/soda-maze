use ark_ff::UniformRand;
use ark_bn254::Bn254;
use ark_ed_on_bn254::{Fq as Fr, Fr as Frr, EdwardsParameters};
use ark_groth16::{Groth16, Proof};
use js_sys::{Uint8Array, Array};
use rand_core::OsRng;
use solana_sdk::signature::Signature;
use wasm_bindgen::{JsValue, prelude::*};
use serde::{Serialize, Deserialize};
use solana_program::{pubkey::Pubkey, instruction::Instruction};
use soda_maze_program::{Packer, params::HEIGHT, core::node::MerkleNode};
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::DepositProof};
use soda_maze_lib::vanilla::deposit::{DepositVanillaProof, DepositOriginInputs, DepositPublicInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, commit::CommitOriginInputs, VanillaProof};

use crate::info;
use crate::utils::*;
use crate::params::*;

type DepositVanillaInstant = DepositVanillaProof::<EdwardsParameters, PoseidonHasher<Fr>>;
type DepositInstant = DepositProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

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
    pub_in: DepositPublicInputs<EdwardsParameters>,
    sig: &Signature,
    nonce: u64,
) -> Instructions {
    use soda_maze_program::instruction::*;

    let reset = reset_deposit_buffer_accounts(vault, depositor).unwrap();

    let leaf = to_maze_fr_repr(pub_in.leaf);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        to_maze_fr_repr(node)
    }).collect::<Vec<_>>();
    let commitment = to_maze_commitment(pub_in.commit.unwrap().commitment);
    let credential = create_deposit_credential(
        vault,
        depositor,
        pub_in.deposit_amount,
        leaf,
        Box::new(updating_nodes),
        commitment,
    ).unwrap();

    let proof = to_maze_proof(proof);
    let verifier = create_deposit_verifier(vault, depositor, Box::new(proof)).unwrap();

    let verify = (0..145u8).into_iter().map(|i| {
        verify_deposit_proof(vault, depositor, vec![i]).unwrap()
    }).collect::<Vec<_>>();

    let utxo = gen_utxo_key(sig, &vault, nonce);
    let finalize = finalize_deposit(vault, token_mint, depositor, pub_in.leaf_index, leaf, utxo).unwrap();

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
    vault: &Pubkey,
    token_mint: &Pubkey,
    depositor: &Pubkey,
    leaf_index: u64, // from vault info
    deposit_amount: u64,
    neighbors: &Array, // get_merkle_neighbor_nodes(vault, leaf_index)
    sig: &Uint8Array,
    nonce: u64,
) -> JsValue {
    console_error_panic_hook::set_once();

    info("Preparing parameters and inputs...");

    let rng = &mut OsRng;
    
    let sig = Signature::new(&sig.to_vec());
    let secret = gen_secret(&sig, &vault);

    let ref nodes_hashes = get_default_node_hashes();
    let neighbor_nodes = neighbors.iter().enumerate().map(|(layer, neighbor)| {
        let data = Uint8Array::from(neighbor).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("Error: merkle node data can not unpack");
            from_maze_fr_repr(node.hash)
        }
    }).collect::<Vec<_>>();
    assert_eq!(neighbor_nodes.len(), HEIGHT, "Error: invalid neighbors array length");

    let const_params = get_deposit_const_params();

    let origin_inputs = DepositOriginInputs {
        leaf_index,
        deposit_amount,
        secret,
        neighbor_nodes,
        commit: Some(CommitOriginInputs {
            nonce: Frr::rand(rng),
        }),
    };

    let pk = get_deposit_pk();
    let pk = pk.into();

    info("Generating vanilla proof...");

    let (pub_in, priv_in) =
        DepositVanillaInstant::generate_vanilla_proof(&const_params, &origin_inputs)
            .expect("Error: generate vanilla proof failed");

    info("Generating snark proof...");

    let proof =
        DepositInstant::generate_snark_proof(rng, &const_params, &pub_in, &priv_in, &pk)
            .expect("Error: generate snark proof failed");
    drop(pk);

    info("Generating solana instructions...");

    let instructions = gen_deposit_instructions(
        *vault,
        *token_mint,
        *depositor,
        proof,
        pub_in,
        &sig,
        nonce,
    );

    JsValue::from_serde(&instructions).unwrap()
}
