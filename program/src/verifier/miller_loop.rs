use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::context::Context512;
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::{ProofType, error::MazeError};
use crate::bn::{BnParameters as Bn, TwistType, Field, doubling_step, addition_step, mul_by_char};

use super::{ProofAC, ProofB};
use super::final_exponent::FinalExponentEasyPart;
use super::fsm::FSM;

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

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MillerLoop {
    pub index: u8,
    pub coeff_index: u8,
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_ac: Pubkey, // ProofAC
    pub proof_b: Pubkey, // ProofB
    pub f: Pubkey, // Fqk254
    pub r: Pubkey, // G2HomProjective254
}

impl MillerLoop {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        mut self,
        proof_type: &ProofType,
        prepared_input_ctx: &Context512<G1Affine254>,
        proof_ac_ctx: &Context512<ProofAC>,
        proof_b_ctx: &Context512<ProofB>,
        r_ctx: &Context512<G2HomProjective254>,
        f_ctx: &Context512<Fqk254>,
        q1_ctx: &Context512<G2Affine254>,
        q2_ctx: &Context512<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_ac_ctx.pubkey() != &self.proof_ac {
            msg!("proof_ac_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_b_ctx.pubkey() != &self.proof_b {
            msg!("proof_b_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let prepared_input = prepared_input_ctx.take()?;
        let proof_ac = proof_ac_ctx.take()?;
        let proof_b = proof_b_ctx.take()?;
        let mut r = r_ctx.borrow_mut()?;
        let mut f = f_ctx.borrow_mut()?;

        let pvk = proof_type.pvk();

        const MAX_LOOP: usize = 2;
        for _ in 0..MAX_LOOP {
            f.square_in_place();

            let coeff = doubling_step(&mut r, FQ_TWO_INV);
            ell(&mut f, &coeff, &proof_ac.proof_a);
            ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);
            ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &proof_ac.proof_c);
            self.coeff_index += 1;

            self.index -= 1;
            let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
            let coeff = match bit {
                1 => addition_step(&mut r, &proof_b),
                -1 => addition_step(&mut r, &(-proof_b)),
                _ => {
                    if self.index == 0 {
                        let q1 = mul_by_char::<BnParameters>(proof_b);
                        let mut q2 = mul_by_char::<BnParameters>(q1);
        
                        if <BnParameters as Bn>::X_IS_NEGATIVE {
                            r.y = -r.y;
                            f.conjugate();
                        }

                        q2.y = -q2.y;
        
                        // in Finalize
                        proof_b_ctx.erase()?;
                        q1_ctx.fill(q1)?;
                        q2_ctx.fill(q2)?;
                        return Ok(FSM::MillerLoopFinalize(MillerLoopFinalize {
                            coeff_index: self.coeff_index,
                            prepared_input: self.prepared_input,
                            proof_ac: self.proof_ac,
                            q1: *q1_ctx.pubkey(),
                            q2: *q2_ctx.pubkey(),
                            r: self.r,
                            f: self.f,
                        }));
                    } else {
                        continue;
                    }
                },
            };

            ell(&mut f, &coeff, &proof_ac.proof_a);
            ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);
            ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &proof_ac.proof_c);
            self.coeff_index += 1;

            // the first value of ATE_LOOP_COUNT is zero, so index will not be zero
            assert_ne!(self.index, 0);
        }
        // next loop
        Ok(FSM::MillerLoop(self))
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MillerLoopFinalize {
    pub coeff_index: u8,
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_ac: Pubkey, // G1Affine254
    pub r: Pubkey, // G2HomProjective254
    pub f: Pubkey, // Fqk254
    pub q1: Pubkey, // G2Affine254
    pub q2: Pubkey, // G2Affine254
}

impl MillerLoopFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        mut self,
        proof_type: &ProofType,
        prepared_input_ctx: &Context512<G1Affine254>,
        proof_ac_ctx: &Context512<ProofAC>,
        r_ctx: &Context512<G2HomProjective254>,
        f_ctx: &Context512<Fqk254>,
        q1_ctx: &Context512<G2Affine254>,
        q2_ctx: &Context512<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_ac_ctx.pubkey() != &self.proof_ac {
            msg!("proof_ac_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let prepared_input = prepared_input_ctx.take()?;
        let proof_ac = proof_ac_ctx.take()?;
        let q1 = q1_ctx.take()?;
        let q2 = q2_ctx.take()?;
        let mut r = r_ctx.borrow_mut()?;
        let mut f = f_ctx.borrow_mut()?;

        let pvk = proof_type.pvk();

        let coeff = addition_step(&mut r, &q1);
        ell(&mut f, &coeff, &proof_ac.proof_a);
        ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);
        ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &proof_ac.proof_c);
        self.coeff_index += 1;

        let coeff = addition_step(&mut r, &q2);
        ell(&mut f, &coeff, &proof_ac.proof_a);
        ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);
        ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &proof_ac.proof_c);

        prepared_input_ctx.erase()?;
        proof_ac_ctx.erase()?;
        q1_ctx.erase()?;
        q2_ctx.erase()?;
        r_ctx.erase()?;
        Ok(FSM::FinalExponentEasyPart(FinalExponentEasyPart {
            r: self.f,
        }))
    }
}
