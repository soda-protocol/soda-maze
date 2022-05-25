use borsh::{BorshSerialize, BorshDeserialize};

use crate::{verifier::{ProofA, ProofB, ProofC}, params::bn::Fr};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum MazeInstruction {
    CreateDepositCredential {
        deposit_amount: u64,
        leaf_index: u64,
        leaf: Fr,
        prev_root: Fr,
        updating_nodes: Box<Vec<Fr>>,
    },
    CreateDepositVerifier {
        commitment: Box<Vec<Fr>>,
        proof_a: Box<ProofA>,
        proof_b: Box<ProofB>,
        proof_c: Box<ProofC>,
    },
    CreateWithdrawCredential {
        withdraw_amount: u64,
        nullifier: Fr,
        leaf_index: u64,
        leaf: Fr,
        prev_root: Fr,
        updating_nodes: Box<Vec<Fr>>,
    },
    CreateWithdrawVerifier {
        proof_a: Box<ProofA>,
        proof_b: Box<ProofB>,
        proof_c: Box<ProofC>,
    },
    VerifyProof,
    FinalizeDeposit,
    FinalizeWithdraw,
    ResetDepositAccounts,
    ResetWithdrawAccounts,
    // 128 ~
    CreateVault,
    ControlVault(bool),
}

