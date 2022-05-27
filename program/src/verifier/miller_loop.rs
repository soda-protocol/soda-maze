use borsh::{BorshSerialize, BorshDeserialize};

use crate::params::{bn::{*, Bn254Parameters as BnParameters}, proof::{PreparedVerifyingKey}};
use crate::bn::{BnParameters as Bn, TwistType, Field, doubling_step, addition_step, mul_by_char};
use crate::verifier::{ProofA, ProofB, ProofC};
use super::program::Program;
use super::final_exponent::FinalExponentEasyPart;

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
    pub ate_index: u8,
    pub coeff_index: u8,
    pub f: Box<Fqk254>, // Fqk254
    pub r: Box<G2HomProjective254>, // G2HomProjective254
    pub prepared_input: Box<G1Affine254>, // G1Affine254
    pub proof_a: Box<ProofA>, // ProofA
    pub proof_b: Box<ProofB>, // ProofB
    pub proof_b_neg: Box<ProofB>, // ProofB
    pub proof_c: Box<ProofC>, // ProofC
}

impl MillerLoop {
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let ate_loop_count_inv = <BnParameters as Bn>::ATE_LOOP_COUNT_INV;

        const MAX_LOOP: usize = 2;
        for _ in 0..MAX_LOOP {
            self.f.square_in_place();

            let coeff = doubling_step(&mut self.r, FQ_TWO_INV);
            ell(&mut self.f, &coeff, &self.proof_a);
            ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
            ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof_c);
            self.coeff_index += 1;

            let bit = ate_loop_count_inv[self.ate_index as usize];
            self.ate_index += 1;
            let coeff = match bit {
                1 => addition_step(&mut self.r, &self.proof_b),
                -1 => addition_step(&mut self.r, &self.proof_b_neg),
                _ => {
                    if (self.ate_index as usize) >= ate_loop_count_inv.len() {
                        let q1 = mul_by_char::<BnParameters>(*self.proof_b);
                        let mut q2 = mul_by_char::<BnParameters>(q1);
        
                        if <BnParameters as Bn>::X_IS_NEGATIVE {
                            self.r.y = -self.r.y;
                            self.f.conjugate();
                        }

                        q2.y = -q2.y;
        
                        // in Finalize
                        return Program::MillerLoopFinalize(MillerLoopFinalize {
                            coeff_index: self.coeff_index,
                            prepared_input: self.prepared_input,
                            proof_a: self.proof_a,
                            proof_c: self.proof_c,
                            q1: Box::new(q1),
                            q2: Box::new(q2),
                            r: self.r,
                            f: self.f,
                        });
                    } else {
                        continue;
                    }
                },
            };
            ell(&mut self.f, &coeff, &self.proof_a);
            ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
            ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof_c);
            self.coeff_index += 1;

            // in ATE_LOOP_COUNT_INV, the last value is zero, so here will never reached
            assert!((self.ate_index as usize) < ate_loop_count_inv.len());
        }

        // next loop
        Program::MillerLoop(self)
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoopFinalize {
    pub coeff_index: u8,
    pub prepared_input: Box<G1Affine254>, // G1Affine254
    pub proof_a: Box<G1Affine254>, // G1Affine254
    pub proof_c: Box<G1Affine254>, // G1Affine254
    pub q1: Box<G2Affine254>, // G2Affine254
    pub q2: Box<G2Affine254>, // G2Affine254
    pub r: Box<G2HomProjective254>, // G2HomProjective254
    pub f: Box<Fqk254>, // Fqk254
}

impl MillerLoopFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let coeff = addition_step(&mut self.r, &self.q1);
        ell(&mut self.f, &coeff, &self.proof_a);
        ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
        ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof_c);
        self.coeff_index += 1;

        let coeff = addition_step(&mut self.r, &self.q2);
        ell(&mut self.f, &coeff, &self.proof_a);
        ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
        ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof_c);

        Program::FinalExponentEasyPart(FinalExponentEasyPart {
            f: self.f,
        })
    }
}
