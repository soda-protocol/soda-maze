use ark_ff::{BigInteger256, PrimeField};
use ark_bn254::{Fr, Bn254};
use ark_groth16::{Groth16, Proof};
use js_sys::{Uint8Array, Array};
use rand_core::OsRng;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::pubkey::Pubkey;
use soda_maze_program::Packer;
use soda_maze_program::params::HEIGHT;
use soda_maze_program::core::node::MerkleNode;
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::WithdrawProof};
use soda_maze_lib::vanilla::withdraw::{WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};

use crate::{log, from_hex, Instructions, ProofResult};
use crate::params::*;

type WithdrawVanillaInstant = WithdrawVanillaProof::<Fr, PoseidonHasher<Fr>>;
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

fn gen_withdraw_instructions(
    vault: Pubkey,
    mint: Pubkey,
    signer: Pubkey,
    proof: Proof<Bn254>,
    pub_in: WithdrawPublicInputs<Fr>,
) -> Instructions {
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::verifier::Proof;
    use soda_maze_program::params::bn::{Fq, Fq2, G1Affine254, G2Affine254};
    use soda_maze_program::instruction::*;
    
    let dst_leaf = BigInteger256::new(pub_in.dst_leaf.into_repr().0);
    let nullifier = BigInteger256::new(pub_in.nullifier.into_repr().0);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        BigInteger256::new(node.into_repr().0)
    }).collect::<Vec<_>>();
    let credential = create_withdraw_credential(
        vault,
        signer,
        pub_in.withdraw_amount,
        nullifier,
        dst_leaf,
        Box::new(updating_nodes),
    ).expect("create withdraw credential failed");

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

    let verifier = create_withdraw_verifier(vault, signer, Box::new(proof))
        .expect("create withdraw verifier failed");

    let verify = (0..170).into_iter().map(|i| {
        verify_proof(vault, signer, vec![i as u8]).expect("verify proof failed")
    }).collect::<Vec<_>>();

    let finalize = finalize_withdraw(vault, mint, signer, pub_in.dst_leaf_index, nullifier)
        .expect("finalize withdraw failed");

    Instructions {
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
    mint: Pubkey,
    signer: Pubkey,
    src_leaf_index: u64,
    balance: u64,
    dst_leaf_index: u64,
    withdraw_amount: u64,
    secret: String,
    src_friends: Array,
    dst_friends: Array,
) -> JsValue {
    console_error_panic_hook::set_once();

    log("Preparing params and datas...");
    
    let ref nodes_hashes = get_default_node_hashes();
    let src_friend_nodes = src_friends.iter().enumerate().map(|(layer, friend)| {
        let data = Uint8Array::from(friend).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.unwrap_state().0)).expect("invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(src_friend_nodes.len(), HEIGHT, "invalid src friends array length");

    let dst_friend_nodes = dst_friends.iter().enumerate().map(|(layer, friend)| {
        let data = Uint8Array::from(friend).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.unwrap_state().0)).expect("invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(dst_friend_nodes.len(), HEIGHT, "invalid dst friends array length");

    let origin_inputs = WithdrawOriginInputs {
        balance,
        withdraw_amount,
        src_leaf_index,
        dst_leaf_index,
        secret: Fr::new(BigInteger256::new(from_hex(secret))),
        src_friend_nodes,
        dst_friend_nodes,
    };

    let withdraw_const_params = get_withdraw_const_params();

    let pk = get_withdraw_pk();
    let pk = pk.into();

    log("Generating vanilla proof...");

    let (pub_in, priv_in) =
        WithdrawVanillaInstant::generate_vanilla_proof(&withdraw_const_params, &origin_inputs)
            .expect("generate vanilla proof failed");

    log("Generating snark proof...");

    let proof =
        WithdrawInstant::generate_snark_proof(&mut OsRng, &withdraw_const_params, &pub_in, &priv_in, &pk)
            .expect("generate snark proof failed");

    log("Generating solana instructions...");

    let res = ProofResult {
        instructions: gen_withdraw_instructions(vault, mint, signer, proof, pub_in),
        output: (dst_leaf_index, balance - withdraw_amount),
    };
    JsValue::from_serde(&res).expect("serde error")
}

