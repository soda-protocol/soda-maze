use std::io::Result;
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, instruction::{Instruction, AccountMeta}, system_program, sysvar};
use spl_associated_token_account::get_associated_token_address;

use crate::ID;
use crate::params::bn::Fr;
use crate::verifier::{ProofA, ProofB, ProofC, get_verifier_pda};
use crate::core::vault::{get_vault_pda, get_vault_authority_pda};
use crate::core::credential::get_credential_pda;
use crate::core::commitment::get_commitment_pda;
use crate::core::node::{get_tree_node_pda, gen_merkle_path_from_leaf_index};
use crate::core::nullifier::get_nullifier_pda;

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

pub fn create_vault(token_mint: Pubkey, admin: Pubkey) -> Result<Instruction> {
    let (vault, _) = get_vault_pda(&admin, &token_mint, &ID);
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);

    let data = MazeInstruction::CreateVault.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(spl_associated_token_account::ID, false),
            AccountMeta::new_readonly(sysvar::ID, false),
            AccountMeta::new_readonly(token_mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_signer, false),
            AccountMeta::new(vault_token_account, false),
            AccountMeta::new_readonly(admin, true),
        ],
        data,
    })
}

pub fn control_vault(vault: Pubkey, admin: Pubkey, enable: bool) -> Result<Instruction> {
    let data = MazeInstruction::ControlVault(enable).try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(admin, true),
        ],
        data,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_deposit_credential(
    vault: Pubkey,
    signer: Pubkey,
    deposit_amount: u64,
    leaf_index: u64,
    leaf: Fr,
    prev_root: Fr,
    updating_nodes: Box<Vec<Fr>>,
) -> Result<Instruction> {
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);

    let data = MazeInstruction::CreateDepositCredential {
        deposit_amount,
        leaf_index,
        leaf,
        prev_root,
        updating_nodes,
    }.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(signer, true),
        ],
        data,
    })
}

pub fn create_deposit_verifier(
    vault: Pubkey,
    signer: Pubkey,
    commitment: Box<Vec<Fr>>,
    proof_a: Box<ProofA>,
    proof_b: Box<ProofB>,
    proof_c: Box<ProofC>,
) -> Result<Instruction> {
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    
    let data = MazeInstruction::CreateDepositVerifier {
        commitment,
        proof_a,
        proof_b,
        proof_c,
    }.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(signer, true),
        ],
        data,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_withdraw_credential(
    vault: Pubkey,
    signer: Pubkey,
    withdraw_amount: u64,
    nullifier: Fr,
    leaf_index: u64,
    leaf: Fr,
    prev_root: Fr,
    updating_nodes: Box<Vec<Fr>>,
) -> Result<Instruction> {
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);

    let data = MazeInstruction::CreateWithdrawCredential {
        withdraw_amount,
        nullifier,
        leaf_index,
        leaf,
        prev_root,
        updating_nodes,
    }.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(signer, true),
        ],
        data,
    })
}

pub fn create_withdraw_verifier(
    vault: Pubkey,
    signer: Pubkey,
    proof_a: Box<ProofA>,
    proof_b: Box<ProofB>,
    proof_c: Box<ProofC>,
) -> Result<Instruction> {
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::CreateWithdrawVerifier {
        proof_a,
        proof_b,
        proof_c,
    }.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(signer, true),
        ],
        data,
    })
}

pub fn verify_proof(vault: Pubkey, signer: Pubkey) -> Result<Instruction> {
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::VerifyProof.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![ AccountMeta::new(verifier, false) ],
        data,
    })
}

pub fn finalize_deposit(
    vault: Pubkey,
    token_mint: Pubkey,
    signer: Pubkey,
    leaf_index: u64,
    leaf: Fr,
) -> Result<Instruction> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (commitment, _) = get_commitment_pda(&vault, &leaf, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&signer, &token_mint);

    let merkle_path = gen_merkle_path_from_leaf_index(leaf_index);
    let nodes_accounts = merkle_path.into_iter().map(|(layer, index)| {
        let (node, _) = get_tree_node_pda(
            &vault,
            layer,
            index,
            &ID,
        );
        AccountMeta::new(node, false)
    }).collect::<Vec<_>>();

    let mut accounts = vec![
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(sysvar::rent::ID, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(credential, false),
        AccountMeta::new(verifier, false),
        AccountMeta::new(commitment, false),
        AccountMeta::new(user_token_account, false),
        AccountMeta::new(vault_token_account, false),
        AccountMeta::new(signer, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeDeposit.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

pub fn finalize_withdraw(
    vault: Pubkey,
    token_mint: Pubkey,
    signer: Pubkey,
    leaf_index: u64,
    nullifier: Fr,
) -> Result<Instruction> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_credential_pda(&vault, &signer, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (nullifier, _) = get_nullifier_pda(&vault, &nullifier, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&signer, &token_mint);

    let merkle_path = gen_merkle_path_from_leaf_index(leaf_index);
    let nodes_accounts = merkle_path.into_iter().map(|(layer, index)| {
        let (node, _) = get_tree_node_pda(
            &vault,
            layer,
            index,
            &ID,
        );
        AccountMeta::new(node, false)
    }).collect::<Vec<_>>();

    let mut accounts = vec![
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(sysvar::rent::ID, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(credential, false),
        AccountMeta::new(verifier, false),
        AccountMeta::new(nullifier, false),
        AccountMeta::new(vault_token_account, false),
        AccountMeta::new(user_token_account, false),
        AccountMeta::new_readonly(vault_signer, false),
        AccountMeta::new(signer, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeWithdraw.try_to_vec()?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}
