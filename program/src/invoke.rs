use solana_program::{
    msg,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    sysvar::{rent::Rent, Sysvar},
    system_instruction,
    program_error::ProgramError,
    instruction::Instruction,
    program::{invoke, invoke_signed},
};
use spl_associated_token_account::instruction::create_associated_token_account;
use spl_token::instruction as token_instruction;

use crate::error::MazeError;

#[inline]
pub fn process_rent_refund<'a>(
    from_info: &AccountInfo<'a>,
    receiver_info: &AccountInfo<'a>,
) {
    **receiver_info.lamports.borrow_mut() = receiver_info
        .lamports()
        .checked_add(from_info.lamports())
        .unwrap();
    **from_info.lamports.borrow_mut() = 0;
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn process_optimal_create_account<'a>(
    rent_info: &AccountInfo<'a>,
    target_account_info: &AccountInfo<'a>,
    payer_info: &AccountInfo<'a>,
    system_program_info: &AccountInfo<'a>,
    owner: &Pubkey,
    data_len: usize,
    signer_seeds: &[&[u8]],
    target_signer_seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::from_account_info(rent_info)?;

    if target_account_info.owner == owner {
        if target_account_info.data_len() != data_len {
            return Err(ProgramError::InvalidAccountData); 
        } else {
            if !rent.is_exempt(target_account_info.lamports(), data_len) {
                msg!("minimum rent: {}", &rent.minimum_balance(data_len));
                return Err(MazeError::NotRentExempt.into());
            } else {
                return Ok(());
            }
        }
    } else if target_account_info.owner != system_program_info.key {
        return Err(ProgramError::IllegalOwner);
    }

    let required_lamports = rent
        .minimum_balance(data_len)
        .saturating_sub(target_account_info.lamports());

    if required_lamports > 0 {
        invoke_optionally_signed(
            &system_instruction::transfer(
                payer_info.key,
                target_account_info.key,
                required_lamports,
            ),
            &[
                payer_info.clone(),
                target_account_info.clone(),
                system_program_info.clone(),
            ],
            signer_seeds,
        )?;
    }

    invoke_optionally_signed(
        &system_instruction::allocate(target_account_info.key, data_len as u64),
        &[target_account_info.clone(), system_program_info.clone()],
        target_signer_seeds,
    )?;

    invoke_optionally_signed(
        &system_instruction::assign(target_account_info.key, owner),
        &[target_account_info.clone(), system_program_info.clone()],
        target_signer_seeds,
    )
}

#[inline(never)]
pub fn process_token_transfer<'a>(
    token_program_info: &AccountInfo<'a>,
    from_account_info: &AccountInfo<'a>,
    to_account_info: &AccountInfo<'a>,
    signer_info: &AccountInfo<'a>,
    signer_seeds: &[&[u8]],
    amount: u64,
) -> ProgramResult {
    invoke_optionally_signed(
        &token_instruction::transfer(
            token_program_info.key,
            from_account_info.key,
            to_account_info.key,
            signer_info.key,
            &[],
            amount,
        )?,
        &[
            from_account_info.clone(),
            to_account_info.clone(),
            signer_info.clone(),
            token_program_info.clone(),
        ],
        signer_seeds,
    )
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn process_create_associated_token_account<'a>(
    rent_info: &AccountInfo<'a>,
    mint_info: &AccountInfo<'a>,
    token_account_info: &AccountInfo<'a>,
    payer_authority_info: &AccountInfo<'a>,
    owner_authority_info: &AccountInfo<'a>,
    token_program_info: &AccountInfo<'a>,
    system_program_info: &AccountInfo<'a>,
    spl_associated_program_info: &AccountInfo<'a>,
    payer_signer_seeds: &[&[u8]],
) -> ProgramResult {
    if token_account_info.owner == system_program_info.key {
        invoke_optionally_signed(
            &create_associated_token_account(
                payer_authority_info.key,
                owner_authority_info.key,
                mint_info.key,
            ),
            &[
                payer_authority_info.clone(),
                owner_authority_info.clone(),
                token_account_info.clone(),
                mint_info.clone(),
                system_program_info.clone(),
                token_program_info.clone(),
                rent_info.clone(),
                spl_associated_program_info.clone(),
            ],
            payer_signer_seeds,
        )
    } else if token_account_info.owner != token_program_info.key {
        Err(ProgramError::IllegalOwner)
    } else {
        Ok(())
    }
}

/// Invoke signed unless signers seeds are empty
#[inline]
pub fn invoke_optionally_signed(
    instruction: &Instruction,
    account_infos: &[AccountInfo],
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    if signer_seeds.is_empty() {
        invoke(instruction, account_infos)
    } else {
        invoke_signed(instruction, account_infos, &[signer_seeds])
    }
}
