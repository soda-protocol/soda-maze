use std::ops::{AddAssign, MulAssign};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::{bn::{BnParameters as Bn, BitIteratorBE, TwistType, Field, doubling_step, addition_step, mul_by_char, Fp12ParamsWrapper, QuadExtParameters, Fp6ParamsWrapper, CubicExtParameters, Fp2ParamsWrapper}, OperationType, error::MazeError, verifier::{ProofA, ProofB, ProofC}};

use super::FSM;
use crate::params::{Fr, Bn254Parameters as BnParameters};
use crate::params::*;
use crate::context::Context;

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
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u8,
    pub public_inputs_1: Pubkey, // Vec<Fr>
    pub public_inputs_2: Pubkey, // Vec<Fr>
    pub public_inputs_3: Pubkey, // Vec<Fr>
    pub g_ic: Pubkey, // G1Projective254
    pub tmp: Pubkey, // G1Projective254
}

impl PrepareInputs {
    pub fn process(
        mut self,
        proof_type: &OperationType,
        public_inputs_1_ctx: &Context<Vec<Fr>>,
        public_inputs_2_ctx: &Context<Vec<Fr>>,
        public_inputs_3_ctx: &Context<Vec<Fr>>,
        g_ic_ctx: &Context<G1Projective254>,
        tmp_ctx: &Context<G1Projective254>,
    ) -> Result<FSM, ProgramError> {
        if public_inputs_1_ctx.pubkey() != &self.public_inputs_1 {
            msg!("public_inputs_1 pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if public_inputs_2_ctx.pubkey() != &self.public_inputs_2 {
            msg!("public_inputs_2 pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if public_inputs_3_ctx.pubkey() != &self.public_inputs_3 {
            msg!("public_inputs_3 pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if g_ic_ctx.pubkey() != &self.g_ic {
            msg!("g_ic_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if tmp_ctx.pubkey() != &self.tmp {
            msg!("tmp_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut public_inputs = public_inputs_1_ctx.take()?;
        public_inputs.extend(public_inputs_2_ctx.take()?);
        public_inputs.extend(public_inputs_3_ctx.take()?);
        
        let mut g_ic = g_ic_ctx.borrow_mut()?;
        let mut tmp = tmp_ctx.borrow_mut()?;

        let public_input = public_inputs[self.input_index as usize];
        let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();
        let bits_len = bits.len();
    
        const MAX_COMPRESS_CYCLE: usize = 8;

        let pvk = proof_type.verifying_key();
        bits
            .into_iter()
            .skip(self.bit_index as usize)
            .take(MAX_COMPRESS_CYCLE)
            .for_each(|bit| {
                tmp.double_in_place();
                if bit {
                    tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
            });
        
        self.bit_index += MAX_COMPRESS_CYCLE as u8;
        if self.bit_index as usize >= bits_len {
            g_ic.add_assign(&tmp);

            self.input_index += 1;
            if public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;

                tmp_ctx.fill(G1Projective254::zero())?;
                Ok(FSM::PrepareInputs(self))
            } else {
                public_inputs_1_ctx.erase()?;
                public_inputs_2_ctx.erase()?;
                public_inputs_3_ctx.erase()?;
                tmp_ctx.erase()?;
                Ok(FSM::PrepareInputsFinalize(PrepareInputsFinalize {
                    g_ic: self.g_ic,
                }))
            }
        } else {
            Ok(FSM::PrepareInputs(self))
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputsFinalize {
    pub g_ic: Pubkey, // G1Projective254
}

impl PrepareInputsFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        proof_a_ctx: &Context<ProofA>,
        proof_b_ctx: &Context<ProofB>,
        proof_c_ctx: &Context<ProofC>,
        g_ic_ctx: &Context<G1Projective254>,
        r_ctx: &Context<G2HomProjective254>,
        f_ctx: &Context<Fqk254>,
        prepared_input_ctx: &Context<G1Affine254>,
    ) -> Result<FSM, ProgramError> {
        if g_ic_ctx.pubkey() != &self.g_ic {
            msg!("g_ic_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let g_ic = g_ic_ctx.take()?;
        let proof_b = proof_b_ctx.take()?;

        let r = G2HomProjective254 {
            x: proof_b.x,
            y: proof_b.y,
            z: Fq2::one(),
        };
        let f = Fqk254::one();

        let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;

        r_ctx.fill(r)?;
        f_ctx.fill(f)?;
        prepared_input_ctx.fill(G1Affine254::from(g_ic))?;
        g_ic_ctx.erase()?;
        Ok(FSM::MillerLoop(MillerLoop {
            step: 1,
            index,
            coeff_index: 0,
            prepared_input: *prepared_input_ctx.pubkey(),
            proof_a: *proof_a_ctx.pubkey(),
            proof_b: *proof_b_ctx.pubkey(),
            proof_c: *proof_c_ctx.pubkey(),
            r: *r_ctx.pubkey(),
            f: *f_ctx.pubkey(),
        }))
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MillerLoop {
    pub step: u8,
    pub index: u8,
    pub coeff_index: u8,
    pub f: Pubkey, // Fqk254
    pub r: Pubkey, // G2HomProjective254
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_a: Pubkey, // ProofA
    pub proof_b: Pubkey, // ProofB
    pub proof_c: Pubkey, // ProofC
}

impl MillerLoop {
    pub fn process_step_0(
        mut self,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;

        f.square_in_place();

        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    pub fn process_step_1(
        mut self,
        proof_a_ctx: &Context<ProofA>,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let proof_a = proof_a_ctx.take()?;
        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.borrow_mut()?;

        let coeff = doubling_step(&mut r, FQ_TWO_INV);
        ell(&mut f, &coeff, &proof_a);
    
        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    pub fn process_step_2(
        mut self,
        proof_type: &OperationType,
        f_ctx: &Context<Fqk254>,
        prepared_input_ctx: &Context<G1Affine254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let prepared_input = prepared_input_ctx.take()?;

        let pvk = proof_type.verifying_key();
        ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);
    
        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_step_3(
        mut self,
        proof_type: &OperationType,
        proof_b_ctx: &Context<ProofB>,
        proof_c_ctx: &Context<ProofC>,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
        q1_ctx: &Context<G2Affine254>,
        q2_ctx: &Context<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if proof_b_ctx.pubkey() != &self.proof_b {
            msg!("proof_b_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_c_ctx.pubkey() != &self.proof_c {
            msg!("proof_c_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let proof_c = proof_c_ctx.take()?;
        let proof_b = proof_b_ctx.take()?;
        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.borrow_mut()?;

        let pvk = proof_type.verifying_key();
        ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &proof_c);

        self.index -= 1;
        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        if bit == 0 {
            if self.index == 0 {
                let q1 = mul_by_char::<BnParameters>(proof_b);
                let mut q2 = mul_by_char::<BnParameters>(q1);

                if <BnParameters as Bn>::X_IS_NEGATIVE {
                    r.y = -r.y;
                    f.conjugate();
                }

                q2.y = -q2.y;

                q1_ctx.fill(q1)?;
                q2_ctx.fill(q2)?;
                proof_b_ctx.erase()?;
                return Ok(FSM::MillerLoopFinalize(MillerLoopFinalize {
                    step: 0,
                    prepared_input: self.prepared_input,
                    proof_a: self.proof_a,
                    proof_c: self.proof_c,
                    q1: *q1_ctx.pubkey(),
                    q2: *q2_ctx.pubkey(),
                    r: self.r,
                    f: self.f,
                }));
            }
        }

        self.coeff_index += 1;
        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    pub fn process_step_4(
        mut self,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
        proof_a_ctx: &Context<ProofA>,
        proof_b_ctx: &Context<ProofB>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_a_ctx.pubkey() != &self.proof_a {
            msg!("proof_a_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_b_ctx.pubkey() != &self.proof_b {
            msg!("proof_b_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.borrow_mut()?;
        let proof_a = proof_a_ctx.take()?;
        let proof_b = proof_b_ctx.take()?;

        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        let coeff = match bit {
            1 => addition_step(&mut r, &proof_b),
            -1 => {
                let neg_b = -proof_b;
                addition_step(&mut r, &neg_b)
            }
            _ => unreachable!("bit is always be 1 or -1 at hear"),
        };
        ell(&mut f, &coeff, &proof_a);

        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    pub fn process_step_5(
        mut self,
        proof_type: &OperationType,
        f_ctx: &Context<Fqk254>,
        prepared_input_ctx: &Context<G1Affine254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let prepared_input = prepared_input_ctx.take()?;

        let pvk = proof_type.verifying_key();
        ell(&mut f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &prepared_input);

        self.step += 1;
        Ok(FSM::MillerLoop(self))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_step_6(
        mut self,
        proof_type: &OperationType,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
        proof_b_ctx: &Context<ProofB>,
        prepared_input_ctx: &Context<G1Affine254>,
        q1_ctx: &Context<G2Affine254>,
        q2_ctx: &Context<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_b_ctx.pubkey() != &self.proof_b {
            msg!("proof_b_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.borrow_mut()?;
        let proof_b = proof_b_ctx.take()?;
        let prepared_input = prepared_input_ctx.take()?;

        let pvk = proof_type.verifying_key();
        ell(&mut f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &prepared_input);

        if self.index == 0 {
            let q1 = mul_by_char::<BnParameters>(proof_b);
            let mut q2 = mul_by_char::<BnParameters>(q1);

            if <BnParameters as Bn>::X_IS_NEGATIVE {
                r.y = -r.y;
                f.conjugate();
            }

            q2.y = -q2.y;

            q1_ctx.fill(q1)?;
            q2_ctx.fill(q2)?;
            proof_b_ctx.erase()?;
            Ok(FSM::MillerLoopFinalize(MillerLoopFinalize {
                step: 0,
                prepared_input: self.prepared_input,
                proof_a: self.proof_a,
                proof_c: self.proof_c,
                q1: *q1_ctx.pubkey(),
                q2: *q2_ctx.pubkey(),
                r: self.r,
                f: self.f,
            }))
        } else {
            self.coeff_index += 1;
            self.step = 0;
            Ok(FSM::MillerLoop(self))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MillerLoopFinalize {
    pub step: u8,
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_a: Pubkey, // G1Affine254
    pub proof_c: Pubkey, // G1Affine254
    pub q1: Pubkey, // G2Affine254
    pub q2: Pubkey, // G2Affine254
    pub r: Pubkey, // G2HomProjective254
    pub f: Pubkey, // Fqk254
}

impl MillerLoopFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process_step_0(
        mut self,
        proof_a_ctx: &Context<ProofA>,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
        q1_ctx: &Context<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if q1_ctx.pubkey() != &self.q1 {
            msg!("q1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_a_ctx.pubkey() != &self.proof_a {
            msg!("proof_a_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.borrow_mut()?;
        let q1 = q1_ctx.take()?;
        let proof_a = proof_a_ctx.take()?;

        let coeff = addition_step(&mut r, &q1);
        ell(&mut f, &coeff, &proof_a);

        self.step += 1;
        q1_ctx.erase()?;
        Ok(FSM::MillerLoopFinalize(self))
    }

    pub fn process_step_1(
        mut self,
        proof_type: &OperationType,
        prepared_input_ctx: &Context<G1Affine254>,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let prepared_input = prepared_input_ctx.take()?;

        let pvk = proof_type.verifying_key();
        let index = pvk.gamma_g2_neg_pc.len() - 2;
        ell(&mut f, &pvk.gamma_g2_neg_pc[index], &prepared_input);

        self.step += 1;
        Ok(FSM::MillerLoopFinalize(self))
    }

    pub fn process_step_2(
        mut self,
        proof_type: &OperationType,
        proof_c_ctx: &Context<ProofC>,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_c_ctx.pubkey() != &self.proof_c {
            msg!("proof_c_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let proof_c = proof_c_ctx.take()?;

        let pvk = proof_type.verifying_key();
        let index = pvk.delta_g2_neg_pc.len() - 2;
        ell(&mut f, &pvk.delta_g2_neg_pc[index], &proof_c);

        self.step += 1;
        Ok(FSM::MillerLoopFinalize(self))
    }

    pub fn process_step_3(
        mut self,
        proof_a_ctx: &Context<ProofA>,
        f_ctx: &Context<Fqk254>,
        r_ctx: &Context<G2HomProjective254>,
        q2_ctx: &Context<G2Affine254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if q2_ctx.pubkey() != &self.q2 {
            msg!("q2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_a_ctx.pubkey() != &self.proof_a {
            msg!("proof_a_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let mut r = r_ctx.take()?;
        let q2 = q2_ctx.take()?;
        let proof_a = proof_a_ctx.take()?;

        let coeff = addition_step(&mut r, &q2);
        ell(&mut f, &coeff, &proof_a);

        self.step += 1;
        r_ctx.erase()?;
        q2_ctx.erase()?;
        proof_a_ctx.erase()?;
        Ok(FSM::MillerLoopFinalize(self))
    }

    pub fn process_step_4(
        mut self,
        proof_type: &OperationType,
        prepared_input_ctx: &Context<G1Affine254>,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if prepared_input_ctx.pubkey() != &self.prepared_input {
            msg!("prepared_input_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let prepared_input = prepared_input_ctx.take()?;

        let pvk = proof_type.verifying_key();
        let index = pvk.gamma_g2_neg_pc.len() - 1;
        ell(&mut f, &pvk.gamma_g2_neg_pc[index], &prepared_input);

        self.step += 1;
        prepared_input_ctx.erase()?;
        Ok(FSM::MillerLoopFinalize(self))
    }

    pub fn process_step_5(
        self,
        proof_type: &OperationType,
        proof_c_ctx: &Context<ProofC>,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if proof_c_ctx.pubkey() != &self.proof_c {
            msg!("proof_c_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let proof_c = proof_c_ctx.take()?;

        let pvk = proof_type.verifying_key();
        let index = pvk.delta_g2_neg_pc.len() - 1;
        ell(&mut f, &pvk.delta_g2_neg_pc[index], &proof_c);
        
        proof_c_ctx.close()?;
        Ok(FSM::FinalExponentInverse0(FinalExponentInverse0 {
            f: self.f,
        }))
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentInverse0 {
    pub f: Pubkey, // Fqk254
}

impl FinalExponentInverse0 {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        f_ctx: &Context<Fqk254>,
        s0_ctx: &Context<Fq2>,
        s1_ctx: &Context<Fq2>,
        s2_ctx: &Context<Fq2>,
        t6_ctx: &Context<Fq2>,
        v0_ctx: &Context<Fq>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let f = f_ctx.take()?;

        if f.is_zero() {
            return Ok(FSM::Finished(false));
        }

        // Guide to Pairing-based Cryptography, Algorithm 5.19.
        // v1 = c1.square()
        let v1 = f.c1.square();
        let v0 = f.c0.square();
        let v0 = Fp12ParamsWrapper::<<BnParameters as Bn>::Fp12Params>::sub_and_mul_base_field_by_nonresidue(&v0, &v1);

        if v0.is_zero() {
            Ok(FSM::Finished(false))
        } else {
            // From "High-Speed Software Implementation of the Optimal Ate AbstractPairing
            // over
            // Barreto-Naehrig Curves"; Algorithm 17
            let t0 = v0.c0.square();
            let t1 = v0.c1.square();
            let t2 = v0.c2.square();
            let t3 = v0.c0 * &v0.c1;
            let t4 = v0.c0 * &v0.c2;
            let t5 = v0.c1 * &v0.c2;
            let n5 = Fp6ParamsWrapper::<<BnParameters as Bn>::Fp6Params>::mul_base_field_by_nonresidue(&t5);

            let s0 = t0 - &n5;
            let s1 = Fp6ParamsWrapper::<<BnParameters as Bn>::Fp6Params>::mul_base_field_by_nonresidue(&t2) - &t3;
            let s2 = t1 - &t4; // typo in paper referenced above. should be "-" as per Scott, but is "*"

            let a1 = v0.c2 * &s1;
            let a2 = v0.c1 * &s2;
            let mut a3 = a1 + &a2;
            a3 = Fp6ParamsWrapper::<<BnParameters as Bn>::Fp6Params>::mul_base_field_by_nonresidue(&a3);

            let t6 = v0.c0 * &s0 + &a3;

            // Guide to Pairing-based Cryptography, Algorithm 5.19.
            // v1 = c1.square()
            let v1 = t6.c1.square();
            let v0 = t6.c0.square();
            let v0 = Fp2ParamsWrapper::<<BnParameters as Bn>::Fp2Params>::sub_and_mul_base_field_by_nonresidue(&v0, &v1);

            s0_ctx.fill(s0)?;
            s1_ctx.fill(s1)?;
            s2_ctx.fill(s2)?;
            t6_ctx.fill(t6)?;
            v0_ctx.fill(v0)?;
            Ok(FSM::FinalExponentInverse1(FinalExponentInverse1 {
                f: self.f,
                s0: *s0_ctx.pubkey(),
                s1: *s1_ctx.pubkey(),
                s2: *s2_ctx.pubkey(),
                t6: *t6_ctx.pubkey(),
                v0: *v0_ctx.pubkey(),
            }))
        }
    }
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentInverse1 {
    pub f: Pubkey, // Fqk254
    pub s0: Pubkey, // Fp2
    pub s1: Pubkey, // Fp2
    pub s2: Pubkey, // Fp2
    pub t6: Pubkey, // Fp2
    pub v0: Pubkey, // Fp
}

impl FinalExponentInverse1 {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        f_ctx: &Context<Fqk254>,
        s0_ctx: &Context<Fq2>,
        s1_ctx: &Context<Fq2>,
        s2_ctx: &Context<Fq2>,
        t6_ctx: &Context<Fq2>,
        v0_ctx: &Context<Fq>,
        f2_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f_ctx.pubkey() != &self.f {
            msg!("f_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if s0_ctx.pubkey() != &self.s0 {
            msg!("s0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if s1_ctx.pubkey() != &self.s1 {
            msg!("s1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if s2_ctx.pubkey() != &self.s2 {
            msg!("s2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if t6_ctx.pubkey() != &self.t6 {
            msg!("t6_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if v0_ctx.pubkey() != &self.v0 {
            msg!("v0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f = f_ctx.borrow_mut()?;
        let s0 = s0_ctx.take()?;
        let s1 = s1_ctx.take()?;
        let s2 = s2_ctx.take()?;
        let t6 = t6_ctx.take()?;
        let v0 = v0_ctx.take()?;

        let f2 = v0
            .inverse()
            .map(|v1| {
                let c0 = t6.c0 * &v1;
                let c1 = -(t6.c1 * &v1);
               
                let t6 = Fq2::new(c0, c1);
                let c0 = t6 * s0;
                let c1 = t6 * s1;
                let c2 = t6 * s2;

                let v1 = Fq6::new(c0, c1, c2);
                let c0 = f.c0 * &v1;
                let c1 = -(f.c1 * &v1);

                Fqk254::new(c0, c1)
            })
            .unwrap();

        f.conjugate();

        f2_ctx.fill(f2)?;
        s0_ctx.erase()?;
        s1_ctx.erase()?;
        s2_ctx.erase()?;
        t6_ctx.erase()?;
        v0_ctx.erase()?;
        Ok(FSM::FinalExponentMul0(FinalExponentMul0 {
            step: 0,
            f1: self.f,
            f2: *f2_ctx.pubkey(),
        }))
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentMul0 {
    pub step: u8,
    pub f1: Pubkey, // Fqk254 
    pub f2: Pubkey, // Fqk254
}

impl FinalExponentMul0 {
    pub fn process_0(
        mut self,
        f1_ctx: &Context<Fqk254>,
        f2_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f1_ctx.pubkey() != &self.f1 {
            msg!("f1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if f2_ctx.pubkey() != &self.f2 {
            msg!("f2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f1 = f1_ctx.borrow_mut()?;
        let mut f2 = f2_ctx.borrow_mut()?;

        // f2 = f^(-1);
        // r = f^(p^6 - 1)
        f1.mul_assign(*f2);

        // f2 = f^(p^6 - 1)
        *f2 = *f1;

        // r = f^((p^6 - 1)(p^2))
        f1.frobenius_map(2);

        self.step += 1;
        Ok(FSM::FinalExponentMul0(self))
    }

    pub fn process_1(
        self,
        f1_ctx: &Context<Fqk254>,
        f2_ctx: &Context<Fqk254>,
        y0_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if f1_ctx.pubkey() != &self.f1 {
            msg!("f1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if f2_ctx.pubkey() != &self.f2 {
            msg!("f2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut f1 = f1_ctx.borrow_mut()?;
        let f2 = f2_ctx.take()?;

        f1.mul_assign(f2);

        y0_ctx.fill(Fqk254::one())?;
        f2_ctx.close()?;
        Ok(FSM::FinalExponentMul1(FinalExponentMul1 {
            step: 1,
            index: 0,
            y0: *y0_ctx.pubkey(),
            r: self.f1,
        }))
    }
}

macro_rules! impl_exp_by_negx_struct {
    ($name:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey, // Fqk254
        }
    };
    ($name:ident, $field0:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident, $field4:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub step: u8,
            pub index: u8,
            pub r: Pubkey,
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
            pub $field4: Pubkey,
        }
    };
}

macro_rules! impl_exp_by_neg_x {
    ($name:ident) => {
        impl $name {
            #[inline]
            fn process_1_inner(
                mut self,
                f_ctx: &Context<Fqk254>,
                res_ctx: &Context<Fqk254>,
            ) -> Result<(Self, bool), ProgramError> {
                let mut res = res_ctx.borrow_mut()?;
                let f = f_ctx.take()?;

                let naf = <BnParameters as Bn>::NAF;
                let value = naf[self.index as usize];
                self.index += 1;

                if value != 0 {
                    self.step = 0;
        
                    if value > 0 {
                        res.mul_assign(f);
                    } else {
                        let mut f_inv = f;
                        f_inv.conjugate();
                        res.mul_assign(f_inv);
                    }
                }

                if (self.index as usize) < naf.len() {
                    Ok((self, true))
                } else {
                    if !<BnParameters as Bn>::X_IS_NEGATIVE {
                        res.conjugate();
                    }
        
                    Ok((self, false))
                }
            }
        }
    };
}

macro_rules! impl_fqk_mul_struct {
    ($name:ident, $field0:ident, $field1:ident, $field2:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
        }
    };
    ($name:ident, $field0:ident, $field1:ident, $field2:ident, $field3:ident, $field4: ident) => {
        #[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
        pub struct $name {
            pub $field0: Pubkey,
            pub $field1: Pubkey,
            pub $field2: Pubkey,
            pub $field3: Pubkey,
            pub $field4: Pubkey,
        }
    };
}

impl_exp_by_negx_struct!(FinalExponentMul1, y0);
impl_exp_by_neg_x!(FinalExponentMul1);

impl FinalExponentMul1 {
    pub fn process_0(
        mut self,
        y0_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y0_ctx.pubkey() != &self.y0 {
            msg!("y0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut res = y0_ctx.borrow_mut()?;

        res.square_in_place();

        self.step += 1;
        Ok(FSM::FinalExponentMul1(self))
    }

    pub fn process_1(
        self,
        r_ctx: &Context<Fqk254>,
        y0_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y0_ctx.pubkey() != &self.y0 {
            msg!("y0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let (s, is_self) = self.process_1_inner(r_ctx, y0_ctx)?;
        if is_self {
            Ok(FSM::FinalExponentMul1(s))
        } else {
            Ok(FSM::FinalExponentMul2(FinalExponentMul2 {
                r: s.r,
                y0: s.y0,
            }))
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentMul2 {
    pub r: Pubkey, // Fqk254
    pub y0: Pubkey, // Fqk254
}

impl FinalExponentMul2 {
    pub fn process(
        self,
        y0_ctx: &Context<Fqk254>,
        y1_ctx: &Context<Fqk254>,
        y2_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y0_ctx.pubkey() != &self.y0 {
            msg!("y0_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y1_ctx.pubkey() != &self.y0 {
            msg!("y1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y2_ctx.pubkey() != &self.y0 {
            msg!("y2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y0 = y0_ctx.take()?;

        let y1 = y0.cyclotomic_square();
        let y2 = y1.cyclotomic_square();

        y0_ctx.erase()?;
        y1_ctx.fill(y1)?;
        y2_ctx.fill(y2)?;
        Ok(FSM::FinalExponentMul3(FinalExponentMul3 {
            r: self.r,
            y1: *y1_ctx.pubkey(),
            y2: *y2_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul3, r, y1, y2);

impl FinalExponentMul3 {
    pub fn process(
        self,
        y1_ctx: &Context<Fqk254>,
        y2_ctx: &Context<Fqk254>,
        y3_ctx: &Context<Fqk254>,
        y4_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y1_ctx.pubkey() != &self.y1 {
            msg!("y1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y2_ctx.pubkey() != &self.y2 {
            msg!("y2_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y1 = y1_ctx.take()?;
        let y2 = y2_ctx.take()?;

        let y3 = y2 * y1;

        y2_ctx.erase()?;
        y3_ctx.fill(y3)?;
        y4_ctx.fill(Fqk254::one())?;
        Ok(FSM::FinalExponentMul4(FinalExponentMul4 {
            step: 1,
            index: 0,
            r: self.r,
            y1: self.y1,
            y3: *y3_ctx.pubkey(),
            y4: *y4_ctx.pubkey(),
        }))
    }
}

impl_exp_by_negx_struct!(FinalExponentMul4, y1, y3, y4);
impl_exp_by_neg_x!(FinalExponentMul4);

impl FinalExponentMul4 {
    pub fn process_0(
        mut self,
        y4_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut res = y4_ctx.borrow_mut()?;

        res.square_in_place();

        self.step += 1;
        Ok(FSM::FinalExponentMul4(self))
    }

    pub fn process_1(
        self,
        y3_ctx: &Context<Fqk254>,
        y4_ctx: &Context<Fqk254>,
        y5_ctx: &Context<Fqk254>,
        y6_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y3_ctx.pubkey() != &self.y3 {
            msg!("y3_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let (s, is_self) = self.process_1_inner(y3_ctx, y4_ctx)?;
        if is_self {
            Ok(FSM::FinalExponentMul4(s))
        } else {
            let y5 = y4_ctx.borrow_mut()?.cyclotomic_square();

            y5_ctx.fill(y5)?;
            y6_ctx.fill(Fqk254::one())?;
            Ok(FSM::FinalExponentMul5(FinalExponentMul5 {
                step: 1,
                index: 0,
                r: s.r,
                y1: s.y1,
                y3: s.y3,
                y4: s.y4,
                y5: *y5_ctx.pubkey(),
                y6: *y6_ctx.pubkey(),
            }))
        }
    }
}

impl_exp_by_negx_struct!(FinalExponentMul5, y1, y3, y4, y5, y6);
impl_exp_by_neg_x!(FinalExponentMul5);

impl FinalExponentMul5 {
    pub fn process_0(
        mut self,
        y6_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y6_ctx.pubkey() != &self.y4 {
            msg!("y6_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut res = y6_ctx.borrow_mut()?;

        res.square_in_place();

        self.step += 1;
        Ok(FSM::FinalExponentMul5(self))
    }

    pub fn process_1(
        self,
        y3_ctx: &Context<Fqk254>,
        y5_ctx: &Context<Fqk254>,
        y6_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y3_ctx.pubkey() != &self.y3 {
            msg!("y3_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y5_ctx.pubkey() != &self.y5 {
            msg!("y5_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y6_ctx.pubkey() != &self.y6 {
            msg!("y6_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let (s, is_self) = self.process_1_inner(y5_ctx, y6_ctx)?;
        if is_self {
            Ok(FSM::FinalExponentMul5(s))
        } else {
            y3_ctx.borrow_mut()?.conjugate();
            y6_ctx.borrow_mut()?.conjugate();
            
            y5_ctx.erase()?;
            Ok(FSM::FinalExponentMul6(FinalExponentMul6 {
                r: s.r,
                y1: s.y1,
                y3: s.y3,
                y4: s.y4,
                y6: s.y6,
            }))
        }
    }
}

impl_fqk_mul_struct!(FinalExponentMul6, r, y1, y3, y4, y6);

impl FinalExponentMul6 {
    pub fn process(
        self,
        y4_ctx: &Context<Fqk254>,
        y6_ctx: &Context<Fqk254>,
        y7_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y6_ctx.pubkey() != &self.y6 {
            msg!("y6_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y4 = y4_ctx.take()?;
        let y6 = y6_ctx.take()?;

        let y7 = y6 * y4;

        y6_ctx.erase()?;
        y7_ctx.fill(y7)?;
        Ok(FSM::FinalExponentMul7(FinalExponentMul7 {
            r: self.r,
            y1: self.y1,
            y3: self.y3,
            y4: self.y4,
            y7: *y7_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul7, r, y1, y3, y4, y7);

impl FinalExponentMul7 {
    pub fn process(
        self,
        y3_ctx: &Context<Fqk254>,
        y7_ctx: &Context<Fqk254>,
        y8_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y3_ctx.pubkey() != &self.y3 {
            msg!("y3_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y7_ctx.pubkey() != &self.y7 {
            msg!("y7_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y3 = y3_ctx.take()?;
        let y7 = y7_ctx.take()?;

        let y8 = y7 * y3;

        y3_ctx.erase()?;
        y7_ctx.erase()?;
        y8_ctx.fill(y8)?;
        Ok(FSM::FinalExponentMul8(FinalExponentMul8 {
            r: self.r,
            y1: self.y1,
            y4: self.y4,
            y8: *y8_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul8, r, y1, y4, y8);

impl FinalExponentMul8 {
    pub fn process(
        self,
        y1_ctx: &Context<Fqk254>,
        y8_ctx: &Context<Fqk254>,
        y9_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y1_ctx.pubkey() != &self.y1 {
            msg!("y1_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y8_ctx.pubkey() != &self.y8 {
            msg!("y8_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y1 = y1_ctx.take()?;
        let y8 = y8_ctx.take()?;

        let y9 = y8 * y1;

        y1_ctx.erase()?;
        y9_ctx.fill(y9)?;
        Ok(FSM::FinalExponentMul9(FinalExponentMul9 {
            r: self.r,
            y4: self.y4,
            y8: self.y8,
            y9: *y9_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul9, r, y4, y8, y9);

impl FinalExponentMul9 {
    pub fn process(
        self,
        y4_ctx: &Context<Fqk254>,
        y8_ctx: &Context<Fqk254>,
        y10_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y4_ctx.pubkey() != &self.y4 {
            msg!("y4_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y8_ctx.pubkey() != &self.y8 {
            msg!("y8_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y4 = y4_ctx.take()?;
        let y8 = y8_ctx.take()?;

        let y10 = y8 * y4;

        y4_ctx.close()?;
        y10_ctx.fill(y10)?;
        Ok(FSM::FinalExponentMul10(FinalExponentMul10 {
            r: self.r,
            y8: self.y8,
            y9: self.y9,
            y10: *y10_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul10, r, y8, y9, y10);

impl FinalExponentMul10 {
    pub fn process(
        self,
        r_ctx: &Context<Fqk254>,
        y10_ctx: &Context<Fqk254>,
        y11_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y10_ctx.pubkey() != &self.y10 {
            msg!("y10_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let r = r_ctx.take()?;
        let y10 = y10_ctx.take()?;

        let y11 = y10 * r;

        y10_ctx.erase()?;
        y11_ctx.fill(y11)?;
        Ok(FSM::FinalExponentMul11(FinalExponentMul11 {
            r: self.r,
            y8: self.y8,
            y9: self.y9,
            y11: *y11_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul11, r, y8, y9, y11);

impl FinalExponentMul11 {
    pub fn process(
        self,
        y9_ctx: &Context<Fqk254>,
        y11_ctx: &Context<Fqk254>,
        y13_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y9_ctx.pubkey() != &self.y9 {
            msg!("y9_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y11_ctx.pubkey() != &self.y11 {
            msg!("y11_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y11 = y11_ctx.take()?;
        let mut y12 = y9_ctx.take()?;
        
        y12.frobenius_map(1);
        let y13 = y12 * y11;

        y11_ctx.erase()?;
        y13_ctx.fill(y13)?;
        Ok(FSM::FinalExponentMul12(FinalExponentMul12 {
            r: self.r,
            y8: self.y8,
            y9: self.y9,
            y13: *y13_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul12, r, y8, y9, y13);

impl FinalExponentMul12 {
    pub fn process(
        self,
        y8_ctx: &Context<Fqk254>,
        y13_ctx: &Context<Fqk254>,
        y14_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y8_ctx.pubkey() != &self.y8 {
            msg!("y8_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y13_ctx.pubkey() != &self.y13 {
            msg!("y13_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut y8 = y8_ctx.take()?;
        let y13 = y13_ctx.take()?;

        y8.frobenius_map(2);
        let y14 = y8 * y13;

        y8_ctx.close()?;
        y13_ctx.erase()?;
        y14_ctx.fill(y14)?;
        Ok(FSM::FinalExponentMul13(FinalExponentMul13 {
            r: self.r,
            y9: self.y9,
            y14: *y14_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentMul13, r, y9, y14);

impl FinalExponentMul13 {
    pub fn process(
        self,
        r_ctx: &Context<Fqk254>,
        y9_ctx: &Context<Fqk254>,
        y15_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if r_ctx.pubkey() != &self.r {
            msg!("r_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y9_ctx.pubkey() != &self.y9 {
            msg!("y9_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let mut r = r_ctx.take()?;
        let y9 = y9_ctx.take()?;

        r.conjugate();
        let y15 = r * y9;

        r_ctx.close()?;
        y9_ctx.close()?;
        y15_ctx.fill(y15)?;
        Ok(FSM::FinalExponentFinalize(FinalExponentFinalize {
            r: self.r,
            y14: self.y14,
            y15: *y15_ctx.pubkey(),
        }))
    }
}

impl_fqk_mul_struct!(FinalExponentFinalize, r, y14, y15);

impl FinalExponentFinalize {
    pub fn process(
        self,
        proof_type: &OperationType,
        y14_ctx: &Context<Fqk254>,
        y15_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if y14_ctx.pubkey() != &self.y14 {
            msg!("y14_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if y15_ctx.pubkey() != &self.y15 {
            msg!("y15_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let y14 = y14_ctx.take()?;
        let mut y15 = y15_ctx.take()?;

        y15.frobenius_map(3);
        let y16 = y15 * y14;

        y14_ctx.close()?;
        y15_ctx.close()?;
        let pvk = proof_type.verifying_key();
        Ok(FSM::Finished(&y16 == pvk.alpha_g1_beta_g2))
    }
}