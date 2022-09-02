use borsh::BorshDeserialize;
use solana_program::{msg, pubkey::Pubkey, account_info::{AccountInfo, next_account_info}};
use solana_program::entrypoint::ProgramResult;

use crate::{
    Packer,
    error::MazeError,
    instruction::MazeInstruction,
    bn::BigInteger256 as BigInteger,
    verifier::{Proof, Verifier, get_verifier_pda},
    core::{
        VanillaData,
        EdwardsAffine,
        nullifier::{get_nullifier_pda, Nullifier},
        commitment::{get_commitment_pda, Commitment, InnerCommitment},
        credential::{get_deposit_credential_pda, get_withdraw_credential_pda},
        deposit::{DepositCredential, DepositVanillaData},
        withdraw::{WithdrawCredential, WithdrawVanillaData},
        vault::{Vault, get_vault_pda, get_vault_authority_pda},
        node::{MerkleNode, get_merkle_node_pda, gen_merkle_path_from_leaf_index},
        utxo::{UTXO, Amount, get_utxo_pda},
    },
    invoke::{
        process_token_transfer,
        process_rent_refund,
        process_optimal_create_account,
        process_optimal_create_token_account,
        process_transfer,
    },
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = MazeInstruction::deserialize(&mut input.as_ref())?;
    match instruction {
        MazeInstruction::CreateDepositCredential {
            deposit_amount,
            leaf,
            updating_nodes,
            commitment,
        } => process_create_deposit_credential(program_id, accounts, deposit_amount, leaf, updating_nodes, commitment),
        MazeInstruction::CreateDepositVerifier {
            proof,
        } => process_create_deposit_verifier(program_id, accounts, proof),
        MazeInstruction::VerifyDepositProof => process_verify_deposit_proof(program_id, accounts),
        MazeInstruction::FinalizeDeposit {
            utxo,
        } => process_finalize_deposit(program_id, accounts, utxo),
        MazeInstruction::CreateWithdrawCredential {
            withdraw_amount,
            receiver,
            nullifier_point,
            leaf,
            updating_nodes,
            commitment,
        } => process_create_withdraw_credential(program_id, accounts, withdraw_amount, receiver, nullifier_point, leaf, updating_nodes, commitment),
        MazeInstruction::CreateWithdrawVerifier {
            proof,
        } => process_create_withdraw_verifier(program_id, accounts, proof),
        MazeInstruction::VerifyWithdrawProof => process_verify_withdraw_proof(program_id, accounts),
        MazeInstruction::FinalizeWithdraw {
            utxo,
            balance_cipher,
        } => process_finalize_withdraw(program_id, accounts, utxo, balance_cipher),
        MazeInstruction::CreateVault {
            min_deposit,
            min_withdraw,
            delegate_fee,
        } => process_create_vault(program_id, accounts, min_deposit, min_withdraw, delegate_fee),
        MazeInstruction::ControlVault(enable) => process_control_vault(program_id, accounts, enable),
    }
}

/////////////////////////////////// Deposit Actions ////////////////////////////////////////

#[inline(never)]
fn process_create_deposit_credential(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deposit_amount: u64,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
    commitment: InnerCommitment,
) -> ProgramResult {
    msg!("Creating deposit credential: deposit amount {}", deposit_amount);

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let depositor_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;
    vault.check_deposit(deposit_amount)?;

    if !depositor_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (credential_key, (seed_1, seed_2, seed_3, seed_4)) = get_deposit_credential_pda(
        vault_info.key,
        depositor_info.key,
        program_id,
    );
    if credential_info.key != &credential_key {
        msg!("Credential pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    if !credential_info.try_data_is_empty()? {
        // clear credential
        credential_info.realloc(0, true)?;
        process_rent_refund(credential_info, depositor_info);
    }
    process_optimal_create_account(
        rent_info,
        credential_info,
        depositor_info,
        system_program_info,
        program_id,
        DepositCredential::LEN,
        &[],
        &[seed_1, seed_2, seed_3, &seed_4],
    )?;

    let vanilla_data = DepositVanillaData::new(
        deposit_amount,
        vault.index,
        leaf,
        vault.root,
        updating_nodes,
        commitment,
    )?;
    // create credential
    let credential = DepositCredential::new(
        *vault_info.key,
        *depositor_info.key,
        vanilla_data,
    );
    credential.initialize_to_account_info(credential_info)
}

#[inline(never)]
fn process_create_deposit_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: Box<Proof>,
) -> ProgramResult {
    msg!("Creating deposit verifier");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let depositor_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;

    let credential = DepositCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    if &credential.owner != depositor_info.key {
        msg!("Depositor pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    // check consistency
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, (seed_1, seed_2)) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    if !verifier_info.try_data_is_empty()? {
        // clear verifier
        verifier_info.realloc(0, true)?;
        process_rent_refund(verifier_info, depositor_info);
    }
    process_optimal_create_account(
        rent_info,
        verifier_info,
        depositor_info,
        system_program_info,
        program_id,
        Verifier::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;
    // create verifier
    let verifier = credential.vanilla_data.to_verifier(proof)?;
    verifier.initialize_to_account_info(verifier_info)
}

fn process_verify_deposit_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Verifying proof");

    let accounts_iter = &mut accounts.iter();

    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;

    let credential = DepositCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    // check consistency
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, _) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    verifier.check_consistency(&credential.vanilla_data)?;

    let verifier = verifier.process();
    verifier.pack_to_account_info(verifier_info)
}

#[inline(never)]
fn process_finalize_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    utxo: [u8; 32],
) -> ProgramResult {
    msg!("Finalizing deposit");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let token_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let commitment_info = next_account_info(accounts_iter)?;
    let src_token_account_info = next_account_info(accounts_iter)?;
    let vault_token_account_info = next_account_info(accounts_iter)?;
    let utxo_info = next_account_info(accounts_iter)?;
    let depositor_info = next_account_info(accounts_iter)?;

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.token_account != vault_token_account_info.key {
        msg!("Vault token account pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    vault.check_enable()?;

    let credential = DepositCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &credential.owner != depositor_info.key {
        msg!("Depositor pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, _) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    verifier.check_consistency(&credential.vanilla_data)?;
    verifier.program.check_verified()?;

    let (commitment_key, (seed_1, seed_2)) = get_commitment_pda(
        &credential.vanilla_data.leaf,
        program_id,
    );
    if &commitment_key != commitment_info.key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        commitment_info,
        depositor_info,
        system_program_info,
        program_id,
        Commitment::LEN,
        &[],
        &[&seed_1, &seed_2],
    )?;
    Commitment::new(credential.vanilla_data.commitment).initialize_to_account_info(commitment_info)?;
    
    // store uxto on chain
    let (utxo_pubkey, (seed_1, seed_2)) = get_utxo_pda(&utxo, program_id);
    if &utxo_pubkey != utxo_info.key {
        msg!("UTXO pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        utxo_info,
        depositor_info,
        system_program_info,
        program_id,
        UTXO::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;
    let utxo = UTXO::new(credential.vanilla_data.leaf_index, Amount::Origin(credential.vanilla_data.deposit_amount));
    utxo.initialize_to_account_info(utxo_info)?;

    let merkle_path = gen_merkle_path_from_leaf_index(vault.index);
    let mut merkle_nodes = credential.vanilla_data.updating_nodes;
    let new_root = merkle_nodes.pop().unwrap();
    merkle_nodes.insert(0, credential.vanilla_data.leaf);
    // check and update merkle nodes
    merkle_nodes
        .into_iter()
        .zip(merkle_path)
        .try_for_each(|(node, (layer, index))| {
            let node_info = next_account_info(accounts_iter)?;
            let (node_key, (seed_1, seed_2, seed_3, seed_4)) = get_merkle_node_pda(
                vault_info.key,
                layer,
                index,
                program_id,
            );
            if &node_key != node_info.key {
                msg!("Node at layer {} index {} is invalid", layer, index);
                return Err(MazeError::UnmatchedAccounts.into());
            }
            process_optimal_create_account(
                rent_info,
                node_info,
                depositor_info,
                system_program_info,
                program_id,
                MerkleNode::LEN,
                &[],
                &[seed_1, &seed_2, &seed_3, &seed_4],
            )?;
            MerkleNode::new(node).pack_to_account_info(node_info)
        })?;
    vault.update(new_root);
    vault.pack_to_account_info(vault_info)?;

    // transfer token from user to vault
    process_token_transfer(
        token_program_info,
        src_token_account_info,
        vault_token_account_info,
        depositor_info,
        &[],
        credential.vanilla_data.deposit_amount,
    )?;
    // clear verifier
    process_rent_refund(verifier_info, depositor_info);
    // clear credential
    process_rent_refund(credential_info, depositor_info);

    Ok(())
}

/////////////////////////////////// Withdraw Actions ////////////////////////////////////////

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn process_create_withdraw_credential(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    withdraw_amount: u64,
    receiver: Pubkey,
    nullifier_point: EdwardsAffine,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
    commitment: InnerCommitment,
) -> ProgramResult {
    msg!("Creating withdraw credential: withdraw amount {}", withdraw_amount);

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let delegator_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;
    vault.check_withdraw(withdraw_amount)?;

    if !delegator_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (credential_key, (seed_1, seed_2, seed_3, seed_4, seed_5)) = get_withdraw_credential_pda(
        vault_info.key,
        delegator_info.key,
        &receiver,
        program_id,
    );
    if credential_info.key != &credential_key {
        msg!("Credential pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    if !credential_info.try_data_is_empty()? {
        // clear credential
        credential_info.realloc(0, true);
        process_rent_refund(credential_info, delegator_info);
    }
    process_optimal_create_account(
        rent_info,
        credential_info,
        delegator_info,
        system_program_info,
        program_id,
        WithdrawCredential::LEN,
        &[],
        &[seed_1, seed_2, seed_3, seed_4, &seed_5],
    )?;

    let vanilla_data = WithdrawVanillaData::new(
        receiver,
        withdraw_amount,
        nullifier_point,
        vault.index,
        leaf,
        vault.root,
        updating_nodes,
        commitment,
    )?;
    // create credential
    let credential = WithdrawCredential::new(
        *vault_info.key,
        *delegator_info.key,
        vanilla_data,
    );
    credential.initialize_to_account_info(credential_info)
}

#[inline(never)]
fn process_create_withdraw_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: Box<Proof>,
) -> ProgramResult {
    msg!("Creating withdraw verifier");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let delegator_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;

    let credential = WithdrawCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    if &credential.owner != delegator_info.key {
        msg!("Delegator pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    // check consistency
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, (seed_1, seed_2)) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !verifier_info.try_data_is_empty()? {
        // clear verifier
        verifier_info.realloc(0, true);
        process_rent_refund(verifier_info, delegator_info);
    }
    process_optimal_create_account(
        rent_info,
        verifier_info,
        delegator_info,
        system_program_info,
        program_id,
        Verifier::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;
    // create verifier
    let verifier = credential.vanilla_data.to_verifier(proof)?;
    verifier.initialize_to_account_info(verifier_info)
}

fn process_verify_withdraw_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Verifying proof");

    let accounts_iter = &mut accounts.iter();

    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_enable()?;

    let credential = WithdrawCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    // check consistency
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, _) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    verifier.check_consistency(&credential.vanilla_data)?;

    let verifier = verifier.process();
    verifier.pack_to_account_info(verifier_info)
}

#[inline(never)]
fn process_finalize_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    utxo: [u8; 32],
    balance_cipher: u128,
) -> ProgramResult {
    msg!("Finalizing withdraw");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let token_program_info = next_account_info(accounts_iter)?;
    let spl_associated_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let token_mint_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let nullifier_info = next_account_info(accounts_iter)?;
    let commitment_info = next_account_info(accounts_iter)?;
    let vault_token_account_info = next_account_info(accounts_iter)?;
    let dst_token_account_info = next_account_info(accounts_iter)?;
    let delegator_token_account_info = next_account_info(accounts_iter)?;
    let vault_signer_info = next_account_info(accounts_iter)?;
    let receiver_info = next_account_info(accounts_iter)?;
    let utxo_info = next_account_info(accounts_iter)?;
    let delegator_info = next_account_info(accounts_iter)?;

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.token_account != vault_token_account_info.key {
        msg!("Vault token account pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &vault.authority != vault_signer_info.key {
        msg!("Vault authority pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    vault.check_enable()?;

    let credential = WithdrawCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &credential.owner != delegator_info.key {
        msg!("Delegator pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &credential.vanilla_data.receiver != receiver_info.key {
        msg!("Receiver pubkey is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    // check if leaf index and root is matched
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (verifier_key, _) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        msg!("Verifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    verifier.check_consistency(&credential.vanilla_data)?;
    verifier.program.check_verified()?;

    let (nullifier_key, (seed_1, seed_2, seed_3)) = get_nullifier_pda(
        &credential.vanilla_data.nullifier_point,
        program_id,
    );
    if &nullifier_key != nullifier_info.key {
        msg!("Nullifier pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        nullifier_info,
        delegator_info,
        system_program_info,
        program_id,
        Nullifier::LEN,
        &[],
        &[&seed_1, &seed_2, &seed_3],
    )?;
    Nullifier::new(credential.vanilla_data.receiver).initialize_to_account_info(nullifier_info)?;

    let (commitment_key, (seed_1, seed_2)) = get_commitment_pda(
        &credential.vanilla_data.leaf,
        program_id,
    );
    if &commitment_key != commitment_info.key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        commitment_info,
        delegator_info,
        system_program_info,
        program_id,
        Commitment::LEN,
        &[],
        &[&seed_1, &seed_2],
    )?;
    Commitment::new(credential.vanilla_data.commitment).initialize_to_account_info(commitment_info)?;

    // store uxto on chain
    let (utxo_pubkey, (seed_1, seed_2)) = get_utxo_pda(&utxo, program_id);
    if &utxo_pubkey != utxo_info.key {
        msg!("UTXO pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        utxo_info,
        delegator_info,
        system_program_info,
        program_id,
        UTXO::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;
    let utxo = UTXO::new(credential.vanilla_data.leaf_index, Amount::Cipher(balance_cipher));
    utxo.initialize_to_account_info(utxo_info)?;

    let merkle_path = gen_merkle_path_from_leaf_index(vault.index);
    let mut merkle_nodes = credential.vanilla_data.updating_nodes;
    let new_root = merkle_nodes.pop().unwrap();
    merkle_nodes.insert(0, credential.vanilla_data.leaf);
    // check and update merkle nodes
    merkle_nodes
        .into_iter()
        .zip(merkle_path)
        .try_for_each(|(node, (layer, index))| {
            let node_info = next_account_info(accounts_iter)?;
            let (node_key, (seed_1, seed_2, seed_3, seed_4)) = get_merkle_node_pda(
                vault_info.key,
                layer,
                index,
                program_id,
            );
            if &node_key != node_info.key {
                msg!("Node at layer {} index {} is invalid", layer, index);
                return Err(MazeError::UnmatchedAccounts.into());
            }
            process_optimal_create_account(
                rent_info,
                node_info,
                delegator_info,
                system_program_info,
                program_id,
                MerkleNode::LEN,
                &[],
                &[seed_1, &seed_2, &seed_3, &seed_4],
            )?;
            MerkleNode::new(node).pack_to_account_info(node_info)
        })?;
    vault.update(new_root);
    vault.pack_to_account_info(vault_info)?;

    process_optimal_create_token_account(
        rent_info,
        token_mint_info,
        dst_token_account_info,
        delegator_info,
        receiver_info,
        token_program_info,
        system_program_info,
        spl_associated_program_info,
        &[],
    )?;

    let receive_amount = credential.vanilla_data.withdraw_amount
        .checked_sub(vault.delegate_fee)
        .ok_or(MazeError::Overflow)?;
    // transfer token from vault to receiver
    process_token_transfer(
        token_program_info,
        vault_token_account_info,
        dst_token_account_info,
        vault_signer_info,
        &vault.signer_seeds(vault_info.key),
        receive_amount,
    )?;
    // transfer token from vault to delegator
    process_token_transfer(
        token_program_info,
        vault_token_account_info,
        delegator_token_account_info,
        vault_signer_info,
        &vault.signer_seeds(vault_info.key),
        vault.delegate_fee,
    )?;

    // transfer `SOL` as fee from delegator to owner if there is less balance.
    const FEE: u64 = 1_000_000;
    if receiver_info.try_lamports()? < FEE {
        let lamports = FEE - receiver_info.try_lamports()?;
        process_transfer(delegator_info, receiver_info, system_program_info, &[], lamports)?;
    }
    // clear verifier
    process_rent_refund(verifier_info, delegator_info);
    // clear credential
    process_rent_refund(credential_info, delegator_info);

    Ok(())
}

/////////////////////////////////////////////////// admin authority ///////////////////////////////////////////////////

#[inline(never)]
fn process_create_vault(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    min_deposit: u64,
    min_withdraw: u64,
    delegate_fee: u64,
) -> ProgramResult {
    msg!("Creating the vault");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let token_program_info = next_account_info(accounts_iter)?;
    let spl_associated_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let token_mint_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let vault_signer_info = next_account_info(accounts_iter)?;
    let vault_token_account_info = next_account_info(accounts_iter)?;
    let admin_info = next_account_info(accounts_iter)?;

    if !admin_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (vault_key, (seed_1, seed_2, seed_3)) = get_vault_pda(
        admin_info.key,
        token_mint_info.key,
        program_id,
    );
    if &vault_key != vault_info.key {
        msg!("Vault pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_optimal_create_account(
        rent_info,
        vault_info,
        admin_info,
        system_program_info,
        program_id,
        Vault::LEN,
        &[],
        &[seed_1, seed_2, &seed_3],
    )?;

    let (vault_signer_key, (_, seed_2)) = get_vault_authority_pda(
        vault_info.key,
        program_id,
    );
    if &vault_signer_key != vault_signer_info.key {
        msg!("Vault signer pubkey is invalid");
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_optimal_create_token_account(
        rent_info,
        token_mint_info,
        vault_token_account_info,
        admin_info,
        vault_signer_info,
        token_program_info,
        system_program_info,
        spl_associated_program_info,
        &[],
    )?;

    let vault = Vault::new(
        *admin_info.key,
        *vault_token_account_info.key,
        vault_signer_key,
        seed_2,
        min_deposit,
        min_withdraw,
        delegate_fee,
    );
    vault.initialize_to_account_info(vault_info)
}

fn process_control_vault(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    enable: bool,
) -> ProgramResult {
    msg!("Controling the vault");

    let accounts_iter = &mut accounts.iter();

    let vault_info = next_account_info(accounts_iter)?;
    let admin_info = next_account_info(accounts_iter)?;

    if !admin_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.admin != admin_info.key {
        msg!("Admin in vault is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    
    vault.enable = enable;

    Ok(())
}
