use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{program_error::ProgramError, account_info::AccountInfo, pubkey::Pubkey, rent::Rent};

use crate::{OperationType, context::Context};

use super::processor::*;

/************************************************************************************************************************************
 
--------------------------------------------------------------------------------------------------------------------------------------
       1        |        2        |        3        |       4        |       5        |      6        |        7      |       8      |
--------------------------------------------------------------------------------------------------------------------------------------
public_inputs_1 | public_inputs_2 | public_inputs_3 |       g_ic     |      tmp       |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       r        |        f        | prepared_input  |       g_ic     |                |     proof_a   |     proof_b   |    proof_c   |
--------------------------------------------------------------------------------------------------------------------------------------
       r        |        f        | prepared_input  |       q1       |       q2       |     proof_a   |     proof_b   |    proof_c   |
--------------------------------------------------------------------------------------------------------------------------------------
       r        |        f        | prepared_input  |       q1       |       q2       |     proof_a   |               |    proof_c   |
--------------------------------------------------------------------------------------------------------------------------------------
       s0       |        f        |        s1       |       s2       |       t6       |      v0       |               |              |
-------------------------------------------------------------------------------------------------------------------------------------
       s0       |        f        |        s1       |       s2       |       t6       |      v0       |       f2      |              |
-------------------------------------------------------------------------------------------------------------------------------------
       y0       |        f1       |                 |                |                |               |       f2      |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y0       |        r        |                 |                |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y0       |                 |        y1       |       y2       |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y3       |                 |        y1       |       y2       |       y4       |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y3       |                 |                 |       y5       |       y4       |       y6      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y3       |                 |                 |       y5       |                |       y6      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
                |                 |                 |       y7       |       y4       |       y6      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y3       |                 |                 |       y7       |                |       y8      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y9       |                 |        y1       |                |                |       y8      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
                |                 |       y10       |                |       y4       |       y8      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
                |        r        |       y10       |       y11      |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y9       |                 |       y13       |       y11      |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
                |                 |       y13       |       y14      |                |       y8      |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
       y9       |        r        |       y15       |                |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------
                |                 |       y15       |       y14      |                |               |               |              |
--------------------------------------------------------------------------------------------------------------------------------------

************************************************************************************************************************************/


#[derive(BorshSerialize, BorshDeserialize)]
pub enum FSM {
    PrepareInputs(PrepareInputs),
    PrepareInputsFinalize(PrepareInputsFinalize),
    MillerLoop(MillerLoop),
    MillerLoopFinalize(MillerLoopFinalize),
    FinalExponentInverse0(FinalExponentInverse0),
    FinalExponentInverse1(FinalExponentInverse1),
    FinalExponentMul0(FinalExponentMul0),
    FinalExponentMul1(FinalExponentMul1),
    FinalExponentMul2(FinalExponentMul2),
    FinalExponentMul3(FinalExponentMul3),
    FinalExponentMul4(FinalExponentMul4),
    FinalExponentMul5(FinalExponentMul5),
    FinalExponentMul6(FinalExponentMul6),
    FinalExponentMul7(FinalExponentMul7),
    FinalExponentMul8(FinalExponentMul8),
    FinalExponentMul9(FinalExponentMul9),
    FinalExponentMul10(FinalExponentMul10),
    FinalExponentMul11(FinalExponentMul11),
    FinalExponentMul12(FinalExponentMul12),
    FinalExponentMul13(FinalExponentMul13),
    FinalExponentFinalize(FinalExponentFinalize),
    Finished(bool),
}

impl FSM {
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub fn process(
        self,
        proof_type: &OperationType,
        program_id: &Pubkey,
        rent: &Rent,
        receiver_info: &AccountInfo,
        buffer_1_info: &AccountInfo,
        buffer_2_info: &AccountInfo,
        buffer_3_info: &AccountInfo,
        buffer_4_info: &AccountInfo,
        buffer_5_info: &AccountInfo,
        buffer_6_info: &AccountInfo,
        buffer_7_info: &AccountInfo,
        buffer_8_info: &AccountInfo,
    ) -> Result<Self, ProgramError> {
        let fsm: Self;

        match self {
            FSM::PrepareInputs(prepare_inputs) => {
                let public_inputs_1_ctx = Context::new(buffer_1_info, program_id)?;
                let public_inputs_2_ctx = Context::new(buffer_2_info, program_id)?;
                let public_inputs_3_ctx = Context::new(buffer_3_info, program_id)?;
                let g_ic_ctx = Context::new(buffer_4_info, program_id)?;
                let tmp_ctx = Context::new(buffer_5_info, program_id)?;

                fsm = prepare_inputs.process(
                    proof_type,
                    &public_inputs_1_ctx,
                    &public_inputs_2_ctx,
                    &public_inputs_3_ctx,
                    &g_ic_ctx,
                    &tmp_ctx,
                )?;

                public_inputs_1_ctx.finalize(rent, receiver_info)?;
                public_inputs_2_ctx.finalize(rent, receiver_info)?;
                public_inputs_3_ctx.finalize(rent, receiver_info)?;
                g_ic_ctx.finalize(rent, receiver_info)?;
                tmp_ctx.finalize(rent, receiver_info)?;
            }
            FSM::PrepareInputsFinalize(prepare_inputs) => {
                let r_ctx = Context::new(buffer_1_info, program_id)?;
                let f_ctx = Context::new(buffer_2_info, program_id)?;
                let prepared_input_ctx = Context::new(buffer_3_info, program_id)?;
                let g_ic_ctx = Context::new(buffer_4_info, program_id)?;
                let proof_a_ctx = Context::new(buffer_6_info, program_id)?;
                let proof_b_ctx = Context::new(buffer_7_info, program_id)?;
                let proof_c_ctx = Context::new(buffer_8_info, program_id)?;

                fsm = prepare_inputs.process(
                    &proof_a_ctx,
                    &proof_b_ctx,
                    &proof_c_ctx,
                    &g_ic_ctx,
                    &r_ctx,
                    &f_ctx,
                    &prepared_input_ctx,
                )?;

                r_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
                prepared_input_ctx.finalize(rent, receiver_info)?;
                g_ic_ctx.finalize(rent, receiver_info)?;
                proof_a_ctx.finalize(rent, receiver_info)?;
                proof_b_ctx.finalize(rent, receiver_info)?;
                proof_c_ctx.finalize(rent, receiver_info)?;
            }
            FSM::MillerLoop(miller_loop) => {
                match miller_loop.step {
                    0 => {
                        let f_ctx = Context::new(buffer_3_info, program_id)?;

                        fsm = miller_loop.process_step_0(&f_ctx)?;

                        f_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let r_ctx = Context::new(buffer_2_info, program_id)?;
                        let f_ctx = Context::new(buffer_3_info, program_id)?;
                        let proof_a_ctx = Context::new(buffer_6_info, program_id)?;

                        fsm = miller_loop.process_step_1(&proof_a_ctx, &f_ctx, &r_ctx)?;

                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        proof_a_ctx.finalize(rent, receiver_info)?;
                    },
                    2 => {
                        let f_ctx = Context::new(buffer_3_info, program_id)?;
                        let prepared_input_ctx = Context::new(buffer_4_info, program_id)?;

                        fsm = miller_loop.process_step_2(proof_type, &f_ctx, &prepared_input_ctx)?;

                        f_ctx.finalize(rent, receiver_info)?;
                        prepared_input_ctx.finalize(rent, receiver_info)?;
                    },
                    3 => {
                        let r_ctx = Context::new(buffer_1_info, program_id)?;
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let q1_ctx = Context::new(buffer_4_info, program_id)?;
                        let q2_ctx = Context::new(buffer_5_info, program_id)?;
                        let proof_b_ctx = Context::new(buffer_7_info, program_id)?;
                        let proof_c_ctx = Context::new(buffer_8_info, program_id)?;

                        fsm = miller_loop.process_step_3(proof_type, &proof_b_ctx, &proof_c_ctx, &f_ctx, &r_ctx, &q1_ctx, &q2_ctx)?;
                        
                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        q1_ctx.finalize(rent, receiver_info)?;
                        q2_ctx.finalize(rent, receiver_info)?;
                        proof_b_ctx.finalize(rent, receiver_info)?;
                        proof_c_ctx.finalize(rent, receiver_info)?;
                    },
                    4 => {
                        let r_ctx = Context::new(buffer_1_info, program_id)?;
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let proof_a_ctx = Context::new(buffer_6_info, program_id)?;
                        let proof_b_ctx = Context::new(buffer_7_info, program_id)?;

                        fsm = miller_loop.process_step_4(&f_ctx, &r_ctx, &proof_a_ctx, &proof_b_ctx)?;
                        
                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        proof_a_ctx.finalize(rent, receiver_info)?;
                        proof_b_ctx.finalize(rent, receiver_info)?;
                    },
                    5 => {
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let prepared_input_ctx = Context::new(buffer_3_info, program_id)?;

                        fsm = miller_loop.process_step_5(proof_type, &f_ctx, &prepared_input_ctx)?;

                        f_ctx.finalize(rent, receiver_info)?;
                        prepared_input_ctx.finalize(rent, receiver_info)?;
                    },
                    6 => {
                        let r_ctx = Context::new(buffer_1_info, program_id)?;
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let prepared_input_ctx = Context::new(buffer_3_info, program_id)?;
                        let q1_ctx = Context::new(buffer_4_info, program_id)?;
                        let q2_ctx = Context::new(buffer_5_info, program_id)?;
                        let proof_b_ctx = Context::new(buffer_7_info, program_id)?;

                        fsm = miller_loop.process_step_6(proof_type, &f_ctx, &r_ctx, &proof_b_ctx, &prepared_input_ctx, &q1_ctx, &q2_ctx)?;

                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        prepared_input_ctx.finalize(rent, receiver_info)?;
                        q1_ctx.finalize(rent, receiver_info)?;
                        q2_ctx.finalize(rent, receiver_info)?;
                        proof_b_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 6]"),
                };
            }
            FSM::MillerLoopFinalize(miller_loop) => {    
                match miller_loop.step {
                    0 => {
                        let r_ctx = Context::new(buffer_1_info, program_id)?;
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let q1_ctx = Context::new(buffer_4_info, program_id)?;
                        let proof_a_ctx = Context::new(buffer_6_info, program_id)?;

                        fsm = miller_loop.process_step_0(&proof_a_ctx, &f_ctx, &r_ctx, &q1_ctx)?;

                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        q1_ctx.finalize(rent, receiver_info)?;
                        proof_a_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let prepared_input_ctx = Context::new(buffer_3_info, program_id)?;

                        fsm = miller_loop.process_step_1(proof_type, &prepared_input_ctx, &f_ctx)?;
                        
                        f_ctx.finalize(rent, receiver_info)?;
                        prepared_input_ctx.finalize(rent, receiver_info)?;
                    },
                    2 => {
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let proof_c_ctx = Context::new(buffer_8_info, program_id)?;
                        
                        fsm = miller_loop.process_step_2(proof_type, &proof_c_ctx, &f_ctx)?;

                        f_ctx.finalize(rent, receiver_info)?;
                        proof_c_ctx.finalize(rent, receiver_info)?;
                    },
                    3 => {
                        let r_ctx = Context::new(buffer_1_info, program_id)?;
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let q2_ctx = Context::new(buffer_5_info, program_id)?;
                        let proof_a_ctx = Context::new(buffer_6_info, program_id)?;
                        
                        fsm = miller_loop.process_step_3(&proof_a_ctx, &f_ctx, &r_ctx, &q2_ctx)?;

                        r_ctx.finalize(rent, receiver_info)?;
                        f_ctx.finalize(rent, receiver_info)?;
                        q2_ctx.finalize(rent, receiver_info)?;
                        proof_a_ctx.finalize(rent, receiver_info)?;
                    },
                    4 => {
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let prepared_input_ctx = Context::new(buffer_3_info, program_id)?;

                        fsm = miller_loop.process_step_4(proof_type, &prepared_input_ctx, &f_ctx)?;
                        
                        f_ctx.finalize(rent, receiver_info)?;
                        prepared_input_ctx.finalize(rent, receiver_info)?;
                    },
                    5 => {
                        let f_ctx = Context::new(buffer_2_info, program_id)?;
                        let proof_c_ctx = Context::new(buffer_8_info, program_id)?;

                        fsm = miller_loop.process_step_5(proof_type, &proof_c_ctx, &f_ctx)?;

                        f_ctx.finalize(rent, receiver_info)?;
                        proof_c_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 5]"),
                };
            }
            FSM::FinalExponentInverse0(final_exponent) => {
                let s0_ctx = Context::new(buffer_1_info, program_id)?;
                let f_ctx = Context::new(buffer_2_info, program_id)?;
                let s1_ctx = Context::new(buffer_3_info, program_id)?;
                let s2_ctx = Context::new(buffer_4_info, program_id)?;
                let t6_ctx = Context::new(buffer_5_info, program_id)?;
                let v0_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&f_ctx, &s0_ctx, &s1_ctx, &s2_ctx, &t6_ctx, &v0_ctx)?;

                s0_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
                s1_ctx.finalize(rent, receiver_info)?;
                s2_ctx.finalize(rent, receiver_info)?;
                t6_ctx.finalize(rent, receiver_info)?;
                v0_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentInverse1(final_exponent) => {
                let s0_ctx = Context::new(buffer_1_info, program_id)?;
                let f_ctx = Context::new(buffer_2_info, program_id)?;
                let s1_ctx = Context::new(buffer_3_info, program_id)?;
                let s2_ctx = Context::new(buffer_4_info, program_id)?;
                let t6_ctx = Context::new(buffer_5_info, program_id)?;
                let v0_ctx = Context::new(buffer_6_info, program_id)?;
                let f2_ctx = Context::new(buffer_7_info, program_id)?;

                fsm = final_exponent.process(&f_ctx, &s0_ctx, &s1_ctx, &s2_ctx, &t6_ctx, &v0_ctx, &f2_ctx)?;

                s0_ctx.finalize(rent, receiver_info)?;
                f_ctx.finalize(rent, receiver_info)?;
                s1_ctx.finalize(rent, receiver_info)?;
                s2_ctx.finalize(rent, receiver_info)?;
                t6_ctx.finalize(rent, receiver_info)?;
                v0_ctx.finalize(rent, receiver_info)?;
                f2_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul0(final_exponent) => {
                match final_exponent.step {
                    0 => {
                        let f1_ctx = Context::new(buffer_2_info, program_id)?;
                        let f2_ctx = Context::new(buffer_7_info, program_id)?; 

                        fsm = final_exponent.process_0(&f1_ctx, &f2_ctx)?;

                        f1_ctx.finalize(rent, receiver_info)?;
                        f2_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let y0_ctx = Context::new(buffer_1_info, program_id)?;
                        let f1_ctx = Context::new(buffer_2_info, program_id)?;
                        let f2_ctx = Context::new(buffer_7_info, program_id)?;

                        fsm = final_exponent.process_1(&f1_ctx, &f2_ctx, &y0_ctx)?;

                        y0_ctx.finalize(rent, receiver_info)?;
                        f1_ctx.finalize(rent, receiver_info)?;
                        f2_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 1]"),
                };
            }
            FSM::FinalExponentMul1(final_exponent) => {
                match final_exponent.step {
                    0 => {
                        let y0_ctx = Context::new(buffer_1_info, program_id)?;

                        fsm = final_exponent.process_0(&y0_ctx)?;

                        y0_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let y0_ctx = Context::new(buffer_1_info, program_id)?;
                        let r_ctx = Context::new(buffer_2_info, program_id)?;

                        fsm = final_exponent.process_1(&r_ctx, &y0_ctx)?;

                        y0_ctx.finalize(rent, receiver_info)?;
                        r_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 1]"),
                };
            }
            FSM::FinalExponentMul2(final_exponent) => {
                let y0_ctx = Context::new(buffer_1_info, program_id)?;
                let y1_ctx = Context::new(buffer_3_info, program_id)?;
                let y2_ctx = Context::new(buffer_4_info, program_id)?;

                fsm = final_exponent.process(&y0_ctx, &y1_ctx, &y2_ctx)?;

                y0_ctx.finalize(rent, receiver_info)?;
                y1_ctx.finalize(rent, receiver_info)?;
                y2_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul3(final_exponent) => {
                let y3_ctx = Context::new(buffer_1_info, program_id)?;
                let y1_ctx = Context::new(buffer_3_info, program_id)?;
                let y2_ctx = Context::new(buffer_4_info, program_id)?;
                let y4_ctx = Context::new(buffer_5_info, program_id)?;

                fsm = final_exponent.process(&y1_ctx, &y2_ctx, &y3_ctx, &y4_ctx)?;

                y3_ctx.finalize(rent, receiver_info)?;
                y1_ctx.finalize(rent, receiver_info)?;
                y2_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul4(final_exponent) => {
                match final_exponent.step {
                    0 => {
                        let y4_ctx = Context::new(buffer_5_info, program_id)?;

                        fsm = final_exponent.process_0(&y4_ctx)?;

                        y4_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let y3_ctx = Context::new(buffer_1_info, program_id)?;
                        let y5_ctx = Context::new(buffer_4_info, program_id)?;
                        let y4_ctx = Context::new(buffer_5_info, program_id)?; 
                        let y6_ctx = Context::new(buffer_6_info, program_id)?; 

                        fsm = final_exponent.process_1(&y3_ctx, &y4_ctx, &y5_ctx, &y6_ctx)?;

                        y3_ctx.finalize(rent, receiver_info)?;
                        y5_ctx.finalize(rent, receiver_info)?;
                        y4_ctx.finalize(rent, receiver_info)?;
                        y6_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 1]"),
                };
            }
            FSM::FinalExponentMul5(final_exponent) => {
                match final_exponent.step {
                    0 => {
                        let y6_ctx = Context::new(buffer_6_info, program_id)?;

                        fsm = final_exponent.process_0(&y6_ctx)?;

                        y6_ctx.finalize(rent, receiver_info)?;
                    },
                    1 => {
                        let y3_ctx = Context::new(buffer_1_info, program_id)?;
                        let y5_ctx = Context::new(buffer_4_info, program_id)?;
                        let y6_ctx = Context::new(buffer_6_info, program_id)?;

                        fsm = final_exponent.process_1(&y3_ctx, &y5_ctx, &y6_ctx)?;

                        y3_ctx.finalize(rent, receiver_info)?;
                        y5_ctx.finalize(rent, receiver_info)?;
                        y6_ctx.finalize(rent, receiver_info)?;
                    },
                    _ => unreachable!("step must be in range [0, 1]"),
                };
            }
            FSM::FinalExponentMul6(final_exponent) => {
                let y7_ctx = Context::new(buffer_4_info, program_id)?;
                let y4_ctx = Context::new(buffer_5_info, program_id)?;
                let y6_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&y4_ctx, &y6_ctx, &y7_ctx)?;

                y7_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                y6_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul7(final_exponent) => {
                let y3_ctx = Context::new(buffer_1_info, program_id)?;
                let y7_ctx = Context::new(buffer_4_info, program_id)?;
                let y8_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&y3_ctx, &y7_ctx, &y8_ctx)?;

                y3_ctx.finalize(rent, receiver_info)?;
                y7_ctx.finalize(rent, receiver_info)?;
                y8_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul8(final_exponent) => {
                let y9_ctx = Context::new(buffer_1_info, program_id)?;
                let y1_ctx = Context::new(buffer_3_info, program_id)?;
                let y8_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&y1_ctx, &y8_ctx, &y9_ctx)?;

                y9_ctx.finalize(rent, receiver_info)?;
                y1_ctx.finalize(rent, receiver_info)?;
                y8_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul9(final_exponent) => {
                let y10_ctx = Context::new(buffer_3_info, program_id)?;
                let y4_ctx = Context::new(buffer_5_info, program_id)?;
                let y8_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&y4_ctx, &y8_ctx, &y10_ctx)?;

                y10_ctx.finalize(rent, receiver_info)?;
                y4_ctx.finalize(rent, receiver_info)?;
                y8_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul10(final_exponent) => {
                let r_ctx = Context::new(buffer_2_info, program_id)?;
                let y10_ctx = Context::new(buffer_3_info, program_id)?;
                let y11_ctx = Context::new(buffer_4_info, program_id)?;

                fsm = final_exponent.process(&r_ctx, &y10_ctx, &y11_ctx)?;
                
                r_ctx.finalize(rent, receiver_info)?;
                y10_ctx.finalize(rent, receiver_info)?;
                y11_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul11(final_exponent) => {
                let y9_ctx = Context::new(buffer_1_info, program_id)?;
                let y13_ctx = Context::new(buffer_3_info, program_id)?;
                let y11_ctx = Context::new(buffer_4_info, program_id)?;

                fsm = final_exponent.process(&y9_ctx, &y11_ctx, &y13_ctx)?;

                y9_ctx.finalize(rent, receiver_info)?;
                y13_ctx.finalize(rent, receiver_info)?;
                y11_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul12(final_exponent) => {
                let y13_ctx = Context::new(buffer_3_info, program_id)?;
                let y14_ctx = Context::new(buffer_4_info, program_id)?;
                let y8_ctx = Context::new(buffer_6_info, program_id)?;

                fsm = final_exponent.process(&y8_ctx, &y13_ctx, &y14_ctx)?;

                y13_ctx.finalize(rent, receiver_info)?;
                y14_ctx.finalize(rent, receiver_info)?;
                y8_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentMul13(final_exponent) => {
                let y9_ctx = Context::new(buffer_1_info, program_id)?;
                let r_ctx = Context::new(buffer_2_info, program_id)?;
                let y15_ctx = Context::new(buffer_3_info, program_id)?;

                fsm = final_exponent.process(&r_ctx, &y9_ctx, &y15_ctx)?;

                y9_ctx.finalize(rent, receiver_info)?;
                r_ctx.finalize(rent, receiver_info)?;
                y15_ctx.finalize(rent, receiver_info)?;
            }
            FSM::FinalExponentFinalize(final_exponent) => {
                let y15_ctx = Context::new(buffer_3_info, program_id)?;
                let y14_ctx = Context::new(buffer_4_info, program_id)?;

                fsm = final_exponent.process(proof_type, &y14_ctx, &y15_ctx)?;

                y15_ctx.finalize(rent, receiver_info)?;
                y14_ctx.finalize(rent, receiver_info)?;
            }
            FSM::Finished(finished) => fsm = FSM::Finished(finished),
        }

        Ok(fsm)
    }
}