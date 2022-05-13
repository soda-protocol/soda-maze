use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::params::{*, Bn254Parameters as BnParameters};
use crate::context::Context;
use crate::bn::{BnParameters as Bn, TwistType, Field, doubling_step, addition_step, mul_by_char};
use crate::{OperationType, error::MazeError, verifier::{ProofA, ProofB, ProofC}};

fn ell(f: &mut Fq12, coeffs: &EllCoeffFq2, p: &G1Affine254) {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;
    let mut c2 = coeffs.2;

    match <BnParameters as Bn>::TWIST_TYPE {
        TwistType::M => {
            c2.mul_assign_by_fp(&p.y);
            c1.mul_assign_by_fp(&p.x);
            f.mul_by_014(&c0, &c1, &c2);
        }
        TwistType::D => {
            c0.mul_assign_by_fp(&p.y);
            c1.mul_assign_by_fp(&p.x);
            f.mul_by_034(&c0, &c1, &c2);
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoop {
    pub step: u8,
    pub index: u8,
    pub coeff_index: u8,
    pub f: Fqk254, // Fqk254
    pub r: G2HomProjective254, // G2HomProjective254
    pub prepared_input: G1Affine254, // G1Affine254
    pub proof_a: ProofA, // ProofA
    pub proof_b: ProofB, // ProofB
    pub proof_c: ProofC, // ProofC
}

impl MillerLoop {
    pub fn process(
        mut self,
        proof_type: &OperationType,
    ) -> Result<(), ProgramError> {
        let pvk = proof_type.verifying_key();

        self.f.square_in_place();

        let coeff = doubling_step(&mut self.r, FQ_TWO_INV);
        ell(&mut self.f, &coeff, &self.proof_a);

        ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
        ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof_c);

        self.index -= 1;
        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        if bit == 0 {
            if self.index == 0 {
                let q1 = mul_by_char::<BnParameters>(self.proof_b);
                let mut q2 = mul_by_char::<BnParameters>(q1);

                if <BnParameters as Bn>::X_IS_NEGATIVE {
                    self.r.y = -self.r.y;
                    self.f.conjugate();
                }

                q2.y = -q2.y;

                return Ok(());
            }
        }

        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        let coeff = match bit {
            1 => addition_step(&mut self.r, &self.proof_b),
            -1 => {
                let neg_b = -self.proof_b;
                addition_step(&mut self.r, &neg_b)
            }
            _ => unreachable!("bit is always be 1 or -1 at hear"),
        };
        ell(&mut self.f, &coeff, &self.proof_a);

        ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
        ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);

        if self.index == 0 {
            let q1 = mul_by_char::<BnParameters>(self.proof_b);
            let mut q2 = mul_by_char::<BnParameters>(q1);

            if <BnParameters as Bn>::X_IS_NEGATIVE {
                self.r.y = -self.r.y;
                self.f.conjugate();
            }

            q2.y = -q2.y;

        } else {
            self.coeff_index += 1;
            self.step = 0;
        }

        Ok(())
    }
}

// #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
// pub struct MillerLoopFinalize {
//     pub step: u8,
//     pub prepared_input: Pubkey, // G1Affine254
//     pub proof_a: Pubkey, // G1Affine254
//     pub proof_c: Pubkey, // G1Affine254
//     pub q1: Pubkey, // G2Affine254
//     pub q2: Pubkey, // G2Affine254
//     pub r: Pubkey, // G2HomProjective254
//     pub f: Pubkey, // Fqk254
// }

// impl MillerLoopFinalize {
//     #[allow(clippy::too_many_arguments)]
//     pub fn process_step_0(
//         mut self,
//         proof_a_ctx: &Context<ProofA>,
//         f_ctx: &Context<Fqk254>,
//         r_ctx: &Context<G2HomProjective254>,
//         q1_ctx: &Context<G2Affine254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if r_ctx.pubkey() != &self.r {
//             msg!("r_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if q1_ctx.pubkey() != &self.q1 {
//             msg!("q1_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if proof_a_ctx.pubkey() != &self.proof_a {
//             msg!("proof_a_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let mut r = r_ctx.borrow_mut()?;
//         let q1 = q1_ctx.take()?;
//         let proof_a = proof_a_ctx.take()?;

//         let coeff = addition_step(&mut r, &q1);
//         ell(&mut f, &coeff, &proof_a);

//         self.step += 1;
//         q1_ctx.erase()?;
//         Ok(FSM::MillerLoopFinalize(self))
//     }

//     pub fn process_step_1(
//         mut self,
//         proof_type: &OperationType,
//         prepared_input_ctx: &Context<G1Affine254>,
//         f_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if prepared_input_ctx.pubkey() != &self.prepared_input {
//             msg!("prepared_input_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let prepared_input = prepared_input_ctx.take()?;

//         let pvk = proof_type.verifying_key();
//         let index = pvk.gamma_g2_neg_pc.len() - 2;
//         ell(&mut f, &pvk.gamma_g2_neg_pc[index], &prepared_input);

//         self.step += 1;
//         Ok(FSM::MillerLoopFinalize(self))
//     }

//     pub fn process_step_2(
//         mut self,
//         proof_type: &OperationType,
//         proof_c_ctx: &Context<ProofC>,
//         f_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if proof_c_ctx.pubkey() != &self.proof_c {
//             msg!("proof_c_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let proof_c = proof_c_ctx.take()?;

//         let pvk = proof_type.verifying_key();
//         let index = pvk.delta_g2_neg_pc.len() - 2;
//         ell(&mut f, &pvk.delta_g2_neg_pc[index], &proof_c);

//         self.step += 1;
//         Ok(FSM::MillerLoopFinalize(self))
//     }

//     pub fn process_step_3(
//         mut self,
//         proof_a_ctx: &Context<ProofA>,
//         f_ctx: &Context<Fqk254>,
//         r_ctx: &Context<G2HomProjective254>,
//         q2_ctx: &Context<G2Affine254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if r_ctx.pubkey() != &self.r {
//             msg!("r_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if q2_ctx.pubkey() != &self.q2 {
//             msg!("q2_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if proof_a_ctx.pubkey() != &self.proof_a {
//             msg!("proof_a_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let mut r = r_ctx.take()?;
//         let q2 = q2_ctx.take()?;
//         let proof_a = proof_a_ctx.take()?;

//         let coeff = addition_step(&mut r, &q2);
//         ell(&mut f, &coeff, &proof_a);

//         self.step += 1;
//         r_ctx.erase()?;
//         q2_ctx.erase()?;
//         proof_a_ctx.erase()?;
//         Ok(FSM::MillerLoopFinalize(self))
//     }

//     pub fn process_step_4(
//         mut self,
//         proof_type: &OperationType,
//         prepared_input_ctx: &Context<G1Affine254>,
//         f_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if prepared_input_ctx.pubkey() != &self.prepared_input {
//             msg!("prepared_input_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let prepared_input = prepared_input_ctx.take()?;

//         let pvk = proof_type.verifying_key();
//         let index = pvk.gamma_g2_neg_pc.len() - 1;
//         ell(&mut f, &pvk.gamma_g2_neg_pc[index], &prepared_input);

//         self.step += 1;
//         prepared_input_ctx.erase()?;
//         Ok(FSM::MillerLoopFinalize(self))
//     }

//     pub fn process_step_5(
//         self,
//         proof_type: &OperationType,
//         proof_c_ctx: &Context<ProofC>,
//         f_ctx: &Context<Fqk254>,
//     ) -> Result<FSM, ProgramError> {
//         if f_ctx.pubkey() != &self.f {
//             msg!("f_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }
//         if proof_c_ctx.pubkey() != &self.proof_c {
//             msg!("proof_c_ctx pubkey mismatch");
//             return Err(MazeError::UnmatchedAccounts.into());
//         }

//         let mut f = f_ctx.borrow_mut()?;
//         let proof_c = proof_c_ctx.take()?;

//         let pvk = proof_type.verifying_key();
//         let index = pvk.delta_g2_neg_pc.len() - 1;
//         ell(&mut f, &pvk.delta_g2_neg_pc[index], &proof_c);
        
//         proof_c_ctx.close()?;
//         Ok(FSM::FinalExponentInverse0(FinalExponentInverse0 {
//             f: self.f,
//         }))
//     }
// }
