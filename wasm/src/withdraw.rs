use ark_ff::UniformRand;
use ark_bn254::Bn254;
use ark_ed_on_bn254::{Fq as Fr, Fr as Frr, EdwardsParameters};
use ark_groth16::{Groth16, Proof};
use serde::{Serialize, Deserialize};
use js_sys::{Uint8Array, Array};
use rand_core::OsRng;
use solana_sdk::signature::Signature;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::{pubkey::Pubkey, instruction::Instruction};
use soda_maze_program::{Packer, params::HEIGHT, core::node::MerkleNode, core::pubkey_to_fr_repr};
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::WithdrawProof};
use soda_maze_lib::vanilla::withdraw::{WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, commit::CommitOriginInputs, VanillaProof};

use crate::info;
use crate::utils::*;
use crate::params::*;

type WithdrawVanillaInstant = WithdrawVanillaProof::<EdwardsParameters, PoseidonHasher<Fr>>;
type WithdrawInstant = WithdrawProof::<EdwardsParameters, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

#[derive(Serialize, Deserialize)]
struct Instructions {
    pub reset: Instruction,
    pub credential: Instruction,
    pub verifier: Instruction,
    pub verify: Vec<Instruction>,
    pub finalize: Instruction,
}

#[allow(clippy::too_many_arguments)]
fn gen_withdraw_instructions(
    vault: Pubkey,
    token_mint: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    proof: Proof<Bn254>,
    pub_in: WithdrawPublicInputs<EdwardsParameters>,
    sig: &Signature,
    nonce: u64,
    balance: u64,
) -> Instructions {
    use soda_maze_program::instruction::*;

    let reset = reset_withdraw_buffer_accounts(vault, receiver, delegator).unwrap();

    let dst_leaf = to_maze_fr_repr(pub_in.dst_leaf);
    let nullifier_point = to_maze_group_affine(pub_in.nullifier_point);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        to_maze_fr_repr(node)
    }).collect::<Vec<_>>();
    let commitment = to_maze_commitment(pub_in.commit.unwrap().commitment);
    let credential = create_withdraw_credential(
        vault,
        receiver,
        delegator,
        pub_in.withdraw_amount,
        nullifier_point.clone(),
        dst_leaf,
        Box::new(updating_nodes),
        commitment,
    ).unwrap();

    let proof = to_maze_proof(proof);
    let verifier = create_withdraw_verifier(vault, receiver, delegator, Box::new(proof)).unwrap();

    let verify = (0..175u8).into_iter().map(|i| {
        verify_withdraw_proof(vault, receiver, vec![i]).unwrap()
    }).collect::<Vec<_>>();

    let balance_cipher = encrypt_balance(sig, &vault, balance);
    let utxo = gen_utxo_key(sig, &vault, nonce);
    let finalize = finalize_withdraw(
        vault,
        token_mint,
        receiver,
        delegator,
        pub_in.dst_leaf_index,
        nullifier_point,
        utxo,
        balance_cipher,
    ).unwrap();

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
pub fn gen_withdraw_proof(
    vault: Pubkey,
    token_mint: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    src_leaf_index: u64, // selected utxo index
    balance: u64, // selected utxo balance
    dst_leaf_index: u64, // from vault info
    withdraw_amount: u64,
    sig: Uint8Array,
    src_neighbors: Array, // get_merkle_neighbor_nodes(vault, src_leaf_index)
    dst_neighbors: Array, // get_merkle_neighbor_nodes(vault, dst_leaf_index)
    nonce: u64,
) -> JsValue {
    console_error_panic_hook::set_once();

    info("Preparing parameters and inputs...");

    let rng = &mut OsRng;
    
    let sig = Signature::new(&sig.to_vec());
    let secret = gen_secret(&sig, &vault);

    let ref nodes_hashes = get_default_node_hashes();
    let src_neighbor_nodes = src_neighbors.iter().enumerate().map(|(layer, neighbor)| {
        let data = Uint8Array::from(neighbor).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("Error: node data can not unpack");
            from_maze_fr_repr(node.hash)
        }
    }).collect::<Vec<_>>();
    assert_eq!(src_neighbor_nodes.len(), HEIGHT, "Error: invalid src neighbors array length");

    let dst_neighbor_nodes = dst_neighbors.iter().enumerate().map(|(layer, neighbor)| {
        let data = Uint8Array::from(neighbor).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("Error: node data can not unpack");
            from_maze_fr_repr(node.hash)
        }
    }).collect::<Vec<_>>();
    assert_eq!(dst_neighbor_nodes.len(), HEIGHT, "Error: invalid dst neighbors array length");

    let withdraw_const_params = get_withdraw_const_params();

    let receiver_fr = from_maze_fr_repr(pubkey_to_fr_repr(&receiver));
    let origin_inputs = WithdrawOriginInputs {
        balance,
        withdraw_amount,
        src_leaf_index,
        dst_leaf_index,
        receiver: receiver_fr,
        secret,
        src_neighbor_nodes,
        dst_neighbor_nodes,
        commit: Some(CommitOriginInputs {
            nonce: Frr::rand(rng),
        }),
    };

    let pk = get_withdraw_pk();
    let pk = pk.into();

    info("Generating vanilla proof...");

    let (pub_in, priv_in) =
        WithdrawVanillaInstant::generate_vanilla_proof(&withdraw_const_params, &origin_inputs)
            .expect("Error: generate vanilla proof failed");

    info("Generating snark proof...");

    let proof =
        WithdrawInstant::generate_snark_proof(rng, &withdraw_const_params, &pub_in, &priv_in, &pk)
            .expect("Error: generate snark proof failed");

    info("Generating solana instructions...");

    let instructions = gen_withdraw_instructions(
        vault,
        token_mint,
        receiver,
        delegator,
        proof,
        pub_in,
        &sig,
        nonce,
        balance - withdraw_amount,
    );
    
    JsValue::from_serde(&instructions).unwrap()
}
