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
        nullifier::{get_nullifier_pda, Nullifier},
        commitment::{get_commitment_pda, Commitment},
        credential::{Credential, get_credential_pda},
        deposit::{DepositCredential, DepositVanillaData},
        withdraw::{WithdrawCredential, WithdrawVanillaData},
        vault::{Vault, get_vault_pda, get_vault_authority_pda},
        node::{MerkleNode, get_merkle_node_pda, gen_merkle_path_from_leaf_index},
    },
    invoke::{
        process_token_transfer,
        process_rent_refund,
        process_optimal_create_account,
        process_create_associated_token_account,
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
        } => process_create_deposit_credential(program_id, accounts, deposit_amount, leaf, updating_nodes),
        MazeInstruction::CreateDepositVerifier {
            commitment,
            proof,
        } => process_create_deposit_verifier(program_id, accounts, commitment, proof),
        MazeInstruction::CreateWithdrawCredential {
            withdraw_amount,
            nullifier,
            leaf,
            updating_nodes,
        } => process_create_withdraw_credential(program_id, accounts, withdraw_amount, nullifier, leaf, updating_nodes),
        MazeInstruction::CreateWithdrawVerifier {
            proof,
        } => process_create_withdraw_verifier(program_id, accounts, proof),
        MazeInstruction::VerifyProof => process_verify_proof(program_id, accounts),
        MazeInstruction::FinalizeDeposit => process_finalize_deposit(program_id, accounts),
        MazeInstruction::FinalizeWithdraw => process_finalize_withdraw(program_id, accounts),
        MazeInstruction::ResetDepositAccounts => process_reset_buffer_accounts::<DepositVanillaData>(program_id, accounts),
        MazeInstruction::ResetWithdrawAccounts => process_reset_buffer_accounts::<WithdrawVanillaData>(program_id, accounts),
        MazeInstruction::CreateVault => process_create_vault(program_id, accounts),
        MazeInstruction::ControlVault(enable) => process_control_vault(program_id, accounts, enable),
    }
}

#[inline(never)]
fn process_create_deposit_credential(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    deposit_amount: u64,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> ProgramResult {
    msg!("Creating deposit credential: deposit amount {}", deposit_amount);

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_valid()?;

    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (credential_key, (seed_1, seed_2, seed_3)) = get_credential_pda(
        vault_info.key,
        signer_info.key,
        program_id,
    );
    if credential_info.key != &credential_key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_optimal_create_account(
        rent_info,
        credential_info,
        signer_info,
        system_program_info,
        program_id,
        DepositCredential::LEN,
        &[],
        &[seed_1, seed_2, &seed_3],
    )?;

    let credential = DepositCredential::new(
        *vault_info.key,
        *signer_info.key,
        DepositVanillaData::new(
            deposit_amount,
            vault.index,
            leaf,
            vault.root,
            updating_nodes,
        ),
    );
    credential.initialize_to_account_info(credential_info)
}

#[inline(never)]
fn process_create_deposit_verifier(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    commitment: Box<Vec<BigInteger>>,
    proof: Box<Proof>,
) -> ProgramResult {
    msg!("Creating deposit verifier");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let mut credential = DepositCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.owner != signer_info.key {
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (verifier_key, (seed_1, seed_2)) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_optimal_create_account(
        rent_info,
        verifier_info,
        signer_info,
        system_program_info,
        program_id,
        Verifier::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;

    credential.vanilla_data.fill_commitment(commitment)?;
    // check if vanilla data is valid
    credential.vanilla_data.check_valid()?;
    // pack
    credential.pack_to_account_info(credential_info)?;

    // create verifier
    let verifier = credential.vanilla_data.to_verifier(*credential_info.key, proof);
    verifier.initialize_to_account_info(verifier_info)
}

#[inline(never)]
fn process_create_withdraw_credential(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    withdraw_amount: u64,
    nullifier: BigInteger,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> ProgramResult {
    msg!("Creating withdraw credential: withdraw amount {}", withdraw_amount);

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    vault.check_valid()?;

    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (credential_key, (seed_1, seed_2, seed_3)) = get_credential_pda(
        vault_info.key,
        signer_info.key,
        program_id,
    );
    if credential_info.key != &credential_key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_optimal_create_account(
        rent_info,
        credential_info,
        signer_info,
        system_program_info,
        program_id,
        WithdrawCredential::LEN,
        &[],
        &[seed_1, seed_2, &seed_3],
    )?;

    let credential = WithdrawCredential::new(
        *vault_info.key,
        *signer_info.key,
        WithdrawVanillaData::new(
            withdraw_amount,
            nullifier,
            vault.index,
            leaf,
            vault.root,
            updating_nodes,
        ),
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
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let credential = WithdrawCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.owner != signer_info.key {
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }

    let (verifier_key, (seed_1, seed_2)) = get_verifier_pda(
        credential_info.key,
        program_id,
    );
    if verifier_info.key != &verifier_key {
        return Ok(());
    }

    process_optimal_create_account(
        rent_info,
        verifier_info,
        signer_info,
        system_program_info,
        program_id,
        Verifier::LEN,
        &[],
        &[seed_1, &seed_2],
    )?;

    // check if vanilla data is valid
    credential.vanilla_data.check_valid()?;

    // create verifier
    let verifier = credential.vanilla_data.to_verifier(*credential_info.key, proof);
    verifier.initialize_to_account_info(verifier_info)
}

pub fn process_verify_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Verifying proof");

    let accounts_iter = &mut accounts.iter();

    let verifier_info = next_account_info(accounts_iter)?;

    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    let verifier = verifier.process();

    verifier.pack_to_account_info(verifier_info)
}

#[inline(never)]
fn process_finalize_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
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
    let signer_info = next_account_info(accounts_iter)?;

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.token_account != vault_token_account_info.key {
        msg!("Token account in vault is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    vault.check_valid()?;

    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    if &verifier.credential != credential_info.key {
        msg!("Credential in verifier is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    verifier.program.check_verified()?;

    let credential = DepositCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault in credential is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &credential.owner != signer_info.key {
        msg!("Signer is not the owner of credential");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;

    let (commitment_key, (seed_1, seed_2, seed_3)) = get_commitment_pda(
        vault_info.key,
        &credential.vanilla_data.leaf,
        program_id,
    );
    if &commitment_key != commitment_info.key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        commitment_info,
        signer_info,
        system_program_info,
        program_id,
        Commitment::LEN,
        &[],
        &[seed_1, &seed_2, &seed_3],
    )?;
    // fill commitment 
    let commitment = credential.vanilla_data.commitment.ok_or(MazeError::LackOfCommiment)?;
    Commitment::new(commitment).initialize_to_account_info(commitment_info)?;
    
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
                signer_info,
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
    // process_token_transfer(
    //     token_program_info,
    //     src_token_account_info,
    //     vault_token_account_info,
    //     signer_info,
    //     &[],
    //     credential.vanilla_data.deposit_amount,
    // )?;

    // clear verifier
    process_rent_refund(verifier_info, signer_info);
    // clear credential
    process_rent_refund(credential_info, signer_info);

    Ok(())
}

#[inline(never)]
fn process_finalize_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Finalizing withdraw");

    let accounts_iter = &mut accounts.iter();

    let system_program_info = next_account_info(accounts_iter)?;
    let token_program_info = next_account_info(accounts_iter)?;
    let rent_info = next_account_info(accounts_iter)?;
    let vault_info = next_account_info(accounts_iter)?;
    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let nullifier_info = next_account_info(accounts_iter)?;
    let vault_token_account_info = next_account_info(accounts_iter)?;
    let dst_token_account_info = next_account_info(accounts_iter)?;
    let vault_signer_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.token_account != vault_token_account_info.key {
        msg!("Token account in vault is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &vault.authority != vault_signer_info.key {
        msg!("Authority in vault is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    vault.check_valid()?;

    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    if &verifier.credential != credential_info.key {
        msg!("Credential in verifier is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    verifier.program.check_verified()?;
    // clear verifier
    process_rent_refund(verifier_info, signer_info);

    let credential = WithdrawCredential::unpack_from_account_info(credential_info, program_id)?;
    if &credential.vault != vault_info.key {
        msg!("Vault in credential is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if &credential.owner != signer_info.key {
        msg!("Signer is not the owner of credential");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }
    // check if leaf index and root is matched
    vault.check_consistency(credential.vanilla_data.leaf_index, &credential.vanilla_data.prev_root)?;
    // clear credential
    process_rent_refund(credential_info, signer_info);

    let (nullifier_key, (seed_1, seed_2, seed_3)) = get_nullifier_pda(
        vault_info.key,
        &credential.vanilla_data.nullifier,
        program_id,
    );
    if &nullifier_key != nullifier_info.key {
        return Err(MazeError::InvalidPdaPubkey.into());
    }
    process_optimal_create_account(
        rent_info,
        nullifier_info,
        signer_info,
        system_program_info,
        program_id,
        Nullifier::LEN,
        &[],
        &[seed_1, &seed_2, &seed_3],
    )?;
    // fill nullifier
    Nullifier::new(()).initialize_to_account_info(nullifier_info)?;

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
                signer_info,
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

    // transfer token from vault to user
    process_token_transfer(
        token_program_info,
        vault_token_account_info,
        dst_token_account_info,
        vault_signer_info,
        &vault.signer_seeds(vault_info.key),
        credential.vanilla_data.withdraw_amount,
    )
}

fn process_reset_buffer_accounts<V: VanillaData>(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Reset buffer accounts");

    let accounts_iter = &mut accounts.iter();

    let credential_info = next_account_info(accounts_iter)?;
    let verifier_info = next_account_info(accounts_iter)?;
    let signer_info = next_account_info(accounts_iter)?;

    let credential = Credential::<V>::unpack_from_account_info(credential_info, program_id)?;
    if &credential.owner != signer_info.key {
        msg!("Signer is not the owner of credential");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !signer_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }
    // clear credential
    process_rent_refund(credential_info, signer_info);

    let verifier = Verifier::unpack_from_account_info(verifier_info, program_id)?;
    if &verifier.credential != credential_info.key {
        msg!("Credential in verifier is invalid");
        return Err(MazeError::UnmatchedAccounts.into());
    }
    // clear verifier
    process_rent_refund(verifier_info, signer_info);

    Ok(())
}

/////////////////////////////////////////////////// admin authority ///////////////////////////////////////////////////

#[inline(never)]
pub fn process_create_vault(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
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
        return Err(MazeError::InvalidPdaPubkey.into());
    }

    process_create_associated_token_account(
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

    let mut vault = Vault::unpack_from_account_info(vault_info, program_id)?;
    if &vault.admin != admin_info.key {
        return Err(MazeError::UnmatchedAccounts.into());
    }
    if !admin_info.is_signer {
        return Err(MazeError::InvalidAuthority.into());
    }
    
    vault.enable = enable;

    Ok(())
}