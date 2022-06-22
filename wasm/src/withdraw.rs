use ark_ff::{BigInteger256, PrimeField};
use ark_bn254::{Fr, Bn254};
use ark_groth16::{Groth16, Proof};
use serde::{Serialize, Deserialize};
use js_sys::{Uint8Array, Array};
use rand_core::OsRng;
use wasm_bindgen::{JsValue, prelude::*};
use solana_program::{pubkey::Pubkey, instruction::Instruction};
use soda_maze_program::{Packer, params::HEIGHT, core::node::MerkleNode};
use soda_maze_lib::circuits::poseidon::PoseidonHasherGadget;
use soda_maze_lib::proof::{ProofScheme, scheme::WithdrawProof};
use soda_maze_lib::vanilla::withdraw::{WithdrawVanillaProof, WithdrawOriginInputs, WithdrawPublicInputs};
use soda_maze_lib::vanilla::{hasher::poseidon::PoseidonHasher, VanillaProof};

use crate::log;
use crate::params::*;

type WithdrawVanillaInstant = WithdrawVanillaProof::<Fr, PoseidonHasher<Fr>>;
type WithdrawInstant = WithdrawProof::<Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>, Groth16<Bn254>>;

#[derive(Serialize, Deserialize)]
struct ProofResult {
    pub instructions: Instructions,
    pub output: (u64, u64),
}

#[derive(Serialize, Deserialize)]
struct Instructions {
    pub reset: Instruction,
    pub credential: Instruction,
    pub verifier: Instruction,
    pub verify: Vec<Instruction>,
    pub token_account: Instruction,
    pub finalize: Instruction,
}

fn gen_withdraw_instructions(
    vault: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    delegator: Pubkey,
    proof: Proof<Bn254>,
    pub_in: WithdrawPublicInputs<Fr>,
    sig: &[u8],
    utxo_id: u64,
    balance: u64,
) -> Instructions {
    use soda_maze_program::bn::BigInteger256;
    use soda_maze_program::verifier::Proof;
    use soda_maze_program::params::bn::{Fq, Fq2, G1Affine254, G2Affine254};
    use soda_maze_program::instruction::*;
    use solana_program::hash::hash;
    use easy_aes::{full_encrypt, BLOCK, Keys};

    let dst_leaf = BigInteger256::new(pub_in.dst_leaf.into_repr().0);
    let nullifier = BigInteger256::new(pub_in.nullifier.into_repr().0);
    let updating_nodes = pub_in.update_nodes.into_iter().map(|node| {
        BigInteger256::new(node.into_repr().0)
    }).collect::<Vec<_>>();
    let credential = create_withdraw_credential(
        vault,
        owner,
        delegator,
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

    let reset = reset_withdraw_buffer_accounts(vault, owner, delegator).expect("reset buffer accounts failed");

    let verifier = create_withdraw_verifier(vault, owner, delegator, Box::new(proof))
        .expect("create withdraw verifier failed");

    let verify = (0..170).into_iter().map(|i| {
        verify_withdraw_proof(vault, owner, vec![i as u8]).expect("verify proof failed")
    }).collect::<Vec<_>>();

    let token_account = spl_associated_token_account::instruction::create_associated_token_account(
        &delegator,
        &owner,
        &mint,
    );

    let seed = hash(sig);
    let key1 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&seed.as_ref()[..16]).expect("invalid key")));
    let key2 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&seed.as_ref()[16..]).expect("invalid key")));
    let mut block = BLOCK::new(u128::from(balance).to_le_bytes());
    full_encrypt(&mut block, &key1);
    full_encrypt(&mut block, &key2);

    let utxo_key = hash(&[sig, &utxo_id.to_le_bytes()].concat());

    let finalize = finalize_withdraw(
        vault,
        mint,
        owner,
        delegator,
        pub_in.dst_leaf_index,
        nullifier,
        utxo_key.to_bytes(),
        block.stringify_block(),
    ).expect("finalize withdraw failed");

    Instructions {
        reset,
        credential,
        verifier,
        verify,
        token_account,
        finalize,
    }
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn gen_withdraw_proof(
    vault: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    delegator: Pubkey,
    src_leaf_index: u64,
    balance: u64,
    dst_leaf_index: u64,
    withdraw_amount: u64,
    sig: Uint8Array,
    src_friends: Array,
    dst_friends: Array,
    utxo_id: u64,
) -> JsValue {
    console_error_panic_hook::set_once();

    log("Preparing params and datas...");
    
    let sig = sig.to_vec();
    let secret = Fr::from_le_bytes_mod_order(&sig);

    let ref nodes_hashes = get_default_node_hashes();
    let src_friend_nodes = src_friends.iter().enumerate().map(|(layer, friend)| {
        let data = Uint8Array::from(friend).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.hash.0)).expect("invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(src_friend_nodes.len(), HEIGHT, "invalid src friends array length");

    let dst_friend_nodes = dst_friends.iter().enumerate().map(|(layer, friend)| {
        let data = Uint8Array::from(friend).to_vec();
        if data.is_empty() {
            nodes_hashes[layer]
        } else {
            let node = MerkleNode::unpack(&data).expect("node data can not unpack");
            Fr::from_repr(BigInteger256::new(node.hash.0)).expect("invalid fr repr")
        }
    }).collect::<Vec<_>>();
    assert_eq!(dst_friend_nodes.len(), HEIGHT, "invalid dst friends array length");

    let origin_inputs = WithdrawOriginInputs {
        balance,
        withdraw_amount,
        src_leaf_index,
        dst_leaf_index,
        secret,
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
        instructions: gen_withdraw_instructions(vault, mint, owner, delegator, proof, pub_in, &sig, utxo_id, balance - withdraw_amount),
        output: (dst_leaf_index, balance - withdraw_amount),
    };
    JsValue::from_serde(&res).expect("serde error")
}
