use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{program_error::ProgramError, account_info::AccountInfo, pubkey::Pubkey, rent::Rent};

use crate::context::Context;
use crate::params::vk::PreparedVerifyingKey;

use super::prepare_inputs::*;
use super::miller_loop::*;
use super::final_exponent::*;

/**********************************************************************************************************************
 
-----------------------------------------------------------------------------------------------------------------------
       1        |        2        |        3        |       4        |       5        |       6       |        7      |
-----------------------------------------------------------------------------------------------------------------------
    proof_ac    |     proof_b     |       g_ic      |       tmp      |  prepare_input |       r       |        f      |
-----------------------------------------------------------------------------------------------------------------------
    proof_ac    |        X        |        q1       |       q2       |  prepare_input |       r       |        f      |
-----------------------------------------------------------------------------------------------------------------------
        X       |        X        |        X        |       X        |        X       |       X       |        r      |
-----------------------------------------------------------------------------------------------------------------------
     r_inv      |        y0       |        X        |       X        |        X       |       X       |        r      |
-----------------------------------------------------------------------------------------------------------------------
     y3_inv     |        y1       |        y3       |       y4       |        X       |       X       |        r      |
-----------------------------------------------------------------------------------------------------------------------
     y5_inv     |        y1       |        y3       |       y4       |       y5       |       y6      |        r      |
-----------------------------------------------------------------------------------------------------------------------
        X       |        y1       |        y8       |       y4       |        X       |       X       |        r      |
-----------------------------------------------------------------------------------------------------------------------
        X       |        X        |        X        |        X       |        X       |       X       |        X      |
-----------------------------------------------------------------------------------------------------------------------

***********************************************************************************************************************/


#[derive(BorshSerialize, BorshDeserialize)]
pub enum FSM {
    PrepareInputs(PrepareInputs),
    MillerLoop(MillerLoop),
    MillerLoopFinalize(MillerLoopFinalize),
    FinalExponentEasyPart(FinalExponentEasyPart),
    FinalExponentHardPart1(FinalExponentHardPart1),
    FinalExponentHardPart2(FinalExponentHardPart2),
    FinalExponentHardPart3(FinalExponentHardPart3),
    FinalExponentHardPart4(FinalExponentHardPart4),
    Finished(bool),
}

impl FSM {
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub fn process(
        self,
        pvk: &PreparedVerifyingKey,
        program_id: &Pubkey,
        rent: &Rent,
        receiver_info: &AccountInfo,
        public_inputs_info: &AccountInfo,
        buffer_1_info: &AccountInfo,
        buffer_2_info: &AccountInfo,
        buffer_3_info: &AccountInfo,
        buffer_4_info: &AccountInfo,
        buffer_5_info: &AccountInfo,
        buffer_6_info: &AccountInfo,
        buffer_7_info: &AccountInfo,
    ) -> Result<Self, ProgramError> {
        let fsm: Self;

        match self {
            FSM::PrepareInputs(prepare_inputs) => {
                let public_inputs_ctx = Context::new(public_inputs_info, program_id)?;
                let proof_b_ctx = Context::new(buffer_2_info, program_id)?;
                let g_ic_ctx = Context::new(buffer_3_info, program_id)?;
                let tmp_ctx = Context::new(buffer_4_info, program_id)?;
                let prepared_input_ctx = Context::new(buffer_5_info, program_id)?;
                let r_ctx = Context::new(buffer_6_info, program_id)?;
                let f_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = prepare_inputs.process(
                    pvk,
                    &public_inputs_ctx,
                    &proof_b_ctx,
                    &g_ic_ctx,
                    &tmp_ctx,
                    &prepared_input_ctx,
                    &r_ctx,
                    &f_ctx,
                )?;

                public_inputs_ctx.finalize(rent, receiver_info)?;
                proof_b_ctx.finalize(rent, receiver_info)?;
                g_ic_ctx.finalize(rent, receiver_info)?;
                tmp_ctx.finalize(rent, receiver_info)?;
                prepared_input_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
            }
            FSM::MillerLoop(miller_loop) => {
                let proof_ac_ctx = Context::new(buffer_1_info, program_id)?;
                let proof_b_ctx = Context::new(buffer_2_info, program_id)?;
                let q1_ctx = Context::new(buffer_3_info, program_id)?;
                let q2_ctx = Context::new(buffer_4_info, program_id)?;
                let prepared_input_ctx = Context::new(buffer_5_info, program_id)?;
                let r_ctx = Context::new(buffer_6_info, program_id)?;
                let f_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = miller_loop.process(
                    pvk,
                    &prepared_input_ctx,
                    &proof_ac_ctx,
                    &proof_b_ctx,
                    &r_ctx,
                    &f_ctx,
                    &q1_ctx,
                    &q2_ctx,
                )?;

                proof_ac_ctx.finalize(rent, receiver_info)?;
                proof_b_ctx.finalize(rent, receiver_info)?;
                q1_ctx.finalize(rent, receiver_info)?;
                q2_ctx.finalize(rent, receiver_info)?;
                prepared_input_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
            }
            FSM::MillerLoopFinalize(miller_loop) => {    
                let proof_ac_ctx = Context::new(buffer_1_info, program_id)?;
                let q1_ctx = Context::new(buffer_3_info, program_id)?;
                let q2_ctx = Context::new(buffer_4_info, program_id)?;
                let prepared_input_ctx = Context::new(buffer_5_info, program_id)?;
                let r_ctx = Context::new(buffer_6_info, program_id)?;
                let f_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = miller_loop.process(
                    pvk,
                    &prepared_input_ctx,
                    &proof_ac_ctx,
                    &r_ctx,
                    &f_ctx,
                    &q1_ctx,
                    &q2_ctx,
                )?;

                proof_ac_ctx.finalize(rent, receiver_info)?;
                q1_ctx.finalize(rent, receiver_info)?;
                q2_ctx.finalize(rent, receiver_info)?;
                prepared_input_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentEasyPart(final_exponent) => {
                let r_inv_ctx = Context::new(buffer_1_info, program_id)?;
                let y0_ctx = Context::new(buffer_2_info, program_id)?;
                let r_ctx = Context::new(buffer_7_info, program_id)?;                
                
                fsm = final_exponent.process(
                    &r_ctx,
                    &r_inv_ctx,
                    &y0_ctx,
                )?;

                r_inv_ctx.finalize(rent, receiver_info)?;
                y0_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentHardPart1(final_exponent) => {
                let r_inv_ctx = Context::new(buffer_1_info, program_id)?;
                let y0_ctx = Context::new(buffer_2_info, program_id)?;
                let y3_ctx = Context::new(buffer_3_info, program_id)?;
                let y4_ctx = Context::new(buffer_4_info, program_id)?;
                let r_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = final_exponent.process(
                    &r_ctx,
                    &r_inv_ctx,
                    &y0_ctx,
                    &y3_ctx,
                    &y4_ctx,
                )?;

                r_inv_ctx.finalize(rent, receiver_info)?;
                y0_ctx.finalize(rent, receiver_info)?;
                y3_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentHardPart2(final_exponent) => {
                let y3_inv_ctx = Context::new(buffer_1_info, program_id)?;
                let y3_ctx = Context::new(buffer_3_info, program_id)?;
                let y4_ctx = Context::new(buffer_4_info, program_id)?;
                let y5_ctx = Context::new(buffer_5_info, program_id)?;
                let y6_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(
                    &y3_ctx,
                    &y3_inv_ctx,
                    &y4_ctx,
                    &y5_ctx,
                    &y6_ctx,
                )?;

                y3_inv_ctx.finalize(rent, receiver_info)?;
                y3_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                y5_ctx.finalize(rent, receiver_info)?;
                y6_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentHardPart3(final_exponent) => {
                let y5_inv_ctx = Context::new(buffer_1_info, program_id)?;
                let y3_ctx = Context::new(buffer_3_info, program_id)?;
                let y4_ctx = Context::new(buffer_4_info, program_id)?;
                let y5_ctx = Context::new(buffer_5_info, program_id)?;
                let y6_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(
                    &y3_ctx,
                    &y4_ctx,
                    &y5_ctx,
                    &y5_inv_ctx,
                    &y6_ctx,
                )?;

                y5_inv_ctx.finalize(rent, receiver_info)?;
                y3_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                y5_ctx.finalize(rent, receiver_info)?;
                y6_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentHardPart4(final_exponent) => {
                let y1_ctx = Context::new(buffer_2_info, program_id)?;
                let y8_ctx = Context::new(buffer_3_info, program_id)?;
                let y4_ctx = Context::new(buffer_4_info, program_id)?;
                let r_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = final_exponent.process(
                    pvk,
                    &r_ctx,
                    &y1_ctx,
                    &y4_ctx,
                    &y8_ctx,
                )?;

                y1_ctx.finalize(rent, receiver_info)?;
                y8_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
            }
            FSM::Finished(finished) => fsm = FSM::Finished(finished),
        }

        Ok(fsm)
    }
}