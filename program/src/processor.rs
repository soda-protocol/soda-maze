use solana_program::{pubkey::Pubkey, account_info::{AccountInfo, next_account_info}};
use solana_program::{entrypoint::ProgramResult, rent::Rent, sysvar::Sysvar};

use crate::{verifier::{ProofA, ProofB, ProofC, ProofAC}, state::{StateWrapper512, VerifyState}};
use crate::{context::Context512, Packer};
use crate::vanilla::vanilla::VanillaInfo;

// #[inline(never)]
// pub fn process_create_vanilla_info(
//     program_id: &Pubkey,
//     accounts: &[AccountInfo],
//     operator: Pubkey,
//     operation: Operation,
// ) -> ProgramResult {
//     let accounts_iter = &mut accounts.iter();

//     let rent = &Rent::from_account_info(next_account_info(accounts_iter)?)?;
//     let vanilla_info = next_account_info(accounts_iter)?;
//     let verify_state_info = next_account_info(accounts_iter)?;
//     let public_inputs_info = next_account_info(accounts_iter)?;
//     let g_ic_info = next_account_info(accounts_iter)?;
//     let tmp_info = next_account_info(accounts_iter)?;

//     // create vanilla info
//     let vanilla = VanillaInfo::new(operation, operator, *verify_state_info.key);
//     vanilla.initialize_to_account_info(&rent, vanilla_info, program_id)?;

//     // create verify stage
//     let public_inputs_ctx = Context::new(public_inputs_info, program_id)?;
//     let g_ic_ctx = Context::new(g_ic_info, program_id)?;
//     let tmp_ctx = Context::new(tmp_info, program_id)?;

//     let verify_state = vanilla.operation.to_verify_state(
//         &g_ic_ctx,
//         &tmp_ctx,
//         &public_inputs_ctx,
//     )?;
//     verify_state.initialize_to_account_info(&rent, verify_state_info, program_id)?;

//     public_inputs_1_ctx.finalize(rent, verify_state_info)?;
//     public_inputs_2_ctx.finalize(rent, verify_state_info)?;
//     public_inputs_3_ctx.finalize(rent, verify_state_info)?;
//     g_ic_ctx.finalize(rent, verify_state_info)?;
//     tmp_ctx.finalize(rent, verify_state_info)?;

//     Ok(())
// }

#[inline(never)]
pub fn process_create_proof_accounts(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof_a: ProofA,
    proof_b: ProofB,
    proof_c: ProofC,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let rent = Rent::from_account_info(next_account_info(accounts_iter)?)?;
    let proof_ac_info = next_account_info(accounts_iter)?;
    let proof_b_info = next_account_info(accounts_iter)?;

    let proof_ac = ProofAC { proof_a, proof_c };
    StateWrapper512::new(proof_ac).initialize_to_account_info(&rent, proof_ac_info, program_id)?;
    StateWrapper512::new(proof_b).initialize_to_account_info(&rent, proof_b_info, program_id)?;

    Ok(())
}

#[inline(never)]
pub fn process_verify_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let rent = &Rent::from_account_info(next_account_info(accounts_iter)?)?;
    let verify_state_info = next_account_info(accounts_iter)?;
    let receiver_info = next_account_info(accounts_iter)?;
    let public_inputs_info = next_account_info(accounts_iter)?;
    let buffer_1_info = next_account_info(accounts_iter)?;
    let buffer_2_info = next_account_info(accounts_iter)?;
    let buffer_3_info = next_account_info(accounts_iter)?;
    let buffer_4_info = next_account_info(accounts_iter)?;
    let buffer_5_info = next_account_info(accounts_iter)?;
    let buffer_6_info = next_account_info(accounts_iter)?;
    let buffer_7_info = next_account_info(accounts_iter)?;

    let verify_state = VerifyState::unpack_from_account_info(verify_state_info, program_id)?;
    let fsm = verify_state.fsm.process(
        program_id,
        rent,
        receiver_info,
        public_inputs_info,
        buffer_1_info,
        buffer_2_info,
        buffer_3_info,
        buffer_4_info,
        buffer_5_info,
        buffer_6_info,
        buffer_7_info,
    )?;

    let verify_state = VerifyState::new(fsm);
    verify_state.pack_to_account_info(verify_state_info)?;

    Ok(())
}


