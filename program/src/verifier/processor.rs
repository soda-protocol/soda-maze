use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};

use crate::{bn::{BnParameters as Bn, BitIteratorBE, TwistType, Field, doubling_step, addition_step, mul_by_char, Fp12ParamsWrapper, QuadExtParameters, Fp6ParamsWrapper, CubicExtParameters, Fp2ParamsWrapper}, OperationType};

use super::{state::{VerifyStage, Proof}, params::*};
use super::params::{Fr, Bn254Parameters as BnParameters};

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

fn exp_by_neg_x(f: &Fqk254, naf: &'static [i8]) -> Fqk254 {
    let mut res = Fqk254::one();
    let mut self_inverse = f.clone();
    self_inverse.conjugate();

    let mut found_nonzero = false;
    for &value in naf.iter().rev() {
        if found_nonzero {
            res.square_in_place();
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                res *= f;
            } else {
                res *= &self_inverse;
            }
        }
    }

    if !<BnParameters as Bn>::X_IS_NEGATIVE {
        res.conjugate();
    }

    res
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputsCtx {
    input_index: u8,
    bit_index: u8,
    g_ic: G1Projective254,
    tmp: G1Projective254,
}

impl PrepareInputsCtx {
    pub fn process(mut self, proof_type: OperationType, public_inputs: &[Fr]) -> VerifyStage {
        let public_input = public_inputs[self.input_index as usize];
        let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();
    
        const MAX_COMPRESS_CYCLE: usize = 4;
        let start = self.bit_index as usize;
        let end = start + MAX_COMPRESS_CYCLE;
        let (end, finished) = if end < bits.len() {
            (end, false)
        } else {
            (bits.len(), true)
        };
    
        let pvk = proof_type.verifying_key();
        for bit in &bits[start..end] {
            self.tmp.double_in_place();
            if *bit {
                self.tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
            }
        }
    
        if finished {
            self.g_ic.add_assign(&self.tmp);
            self.input_index += 1;
            if public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;
                self.tmp = G1Projective254::zero();
                self.g_ic = *pvk.g_ic_init;
    
                VerifyStage::PrepareInputs(self)
            } else {
                VerifyStage::FinalizeInputs(FinalizeInputsCtx(self.g_ic))
            }
        } else {
            self.bit_index = end as u8;
            VerifyStage::PrepareInputs(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalizeInputsCtx(G1Projective254);

impl FinalizeInputsCtx {
    pub fn process(self, proof: Proof) -> VerifyStage {
        let prepared_input = G1Affine254::from(self.0);
        let r = G2HomProjective254 {
            x: proof.b.x,
            y: proof.b.y,
            z: Fq2::one(),
        };

        let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;
        VerifyStage::MillerLoop(MillerLoopCtx {
            step: 1,
            index,
            coeff_index: 0,
            prepared_input,
            proof,
            r,
            f: Fqk254::one(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoopCtx {
    pub step: u8,
    pub index: u8,
    pub coeff_index: u8,
    pub prepared_input: G1Affine254,
    pub proof: Proof,
    pub r: G2HomProjective254,
    pub f: Fqk254,
}

impl MillerLoopCtx {
    pub fn process(mut self, proof_type: OperationType) -> VerifyStage {
        match self.step {
            0 => {
                self.f.square_in_place();

                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            1 => {
                let coeff = doubling_step(&mut self.r, FQ_TWO_INV);
                ell(&mut self.f, &coeff, &self.proof.a);
            
                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            2 => {
                let pvk = proof_type.verifying_key();
                ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);
            
                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            3 => {
                let pvk = proof_type.verifying_key();
                ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.proof.c);

                self.index -= 1;
                let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
                if bit == 0 {
                    if self.index == 0 {
                        let q1 = mul_by_char::<BnParameters>(self.proof.b);
                        let mut q2 = mul_by_char::<BnParameters>(q1);
        
                        if <BnParameters as Bn>::X_IS_NEGATIVE {
                            self.r.y = -self.r.y;
                            self.f.conjugate();
                        }
        
                        q2.y = -q2.y;
                        return VerifyStage::MillerFinalize(MillerFinalizeCtx {
                            step: 0,
                            prepared_input: self.prepared_input,
                            proof_a: self.proof.a,
                            proof_c: self.proof.c,
                            q1,
                            q2,
                            r: self.r,
                            f: self.f,
                        });
                    }
                }

                self.coeff_index += 1;
                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            4 => {
                let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
                let coeff = match bit {
                    1 => addition_step(&mut self.r, &self.proof.b),
                    -1 => {
                        let neg_b = -self.proof.b;
                        addition_step(&mut self.r, &neg_b)
                    }
                    _ => unreachable!("bit is always be 1 or -1 at hear"),
                };
                ell(&mut self.f, &coeff, &self.proof.a);

                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            5 => {
                let pvk = proof_type.verifying_key();
                ell(&mut self.f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);

                self.step += 1;
                VerifyStage::MillerLoop(self)
            }
            6 => {
                let pvk = proof_type.verifying_key();
                ell(&mut self.f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], &self.prepared_input);

                if self.index == 0 {
                    let q1 = mul_by_char::<BnParameters>(self.proof.b);
                    let mut q2 = mul_by_char::<BnParameters>(q1);
    
                    if <BnParameters as Bn>::X_IS_NEGATIVE {
                        self.r.y = -self.r.y;
                        self.f.conjugate();
                    }
    
                    q2.y = -q2.y;
                    VerifyStage::MillerFinalize(MillerFinalizeCtx {
                        step: 0,
                        prepared_input: self.prepared_input,
                        proof_a: self.proof.a,
                        proof_c: self.proof.c,
                        q1,
                        q2,
                        r: self.r,
                        f: self.f,
                    })
                } else {
                    self.coeff_index += 1;
                    self.step = 0;
                    VerifyStage::MillerLoop(self)
                }
            }
            _ => unreachable!("step is always in range [0, 6]"),
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerFinalizeCtx {
    pub step: u8,
    pub prepared_input: G1Affine254,
    pub proof_a: G1Affine254,
    pub proof_c: G1Affine254,
    pub q1: G2Affine254,
    pub q2: G2Affine254,
    pub r: G2HomProjective254,
    pub f: Fqk254,
}

impl MillerFinalizeCtx {
    pub fn process(mut self, proof_type: OperationType) -> VerifyStage {
        match self.step {
            0 => {
                let coeff = addition_step(&mut self.r, &self.q1);
                ell(&mut self.f, &coeff, &self.proof_a);

                self.step += 1;
                VerifyStage::MillerFinalize(self)
            }
            1 => {
                let pvk = proof_type.verifying_key();
                let index = pvk.gamma_g2_neg_pc.len() - 2;
                ell(&mut self.f, &pvk.gamma_g2_neg_pc[index], &self.prepared_input);

                self.step += 1;
                VerifyStage::MillerFinalize(self)
            }
            2 => {
                let pvk = proof_type.verifying_key();
                let index = pvk.delta_g2_neg_pc.len() - 2;
                ell(&mut self.f, &pvk.delta_g2_neg_pc[index], &self.proof_c);

                self.step += 1;
                VerifyStage::MillerFinalize(self) 
            }
            3 => {
                let coeff = addition_step(&mut self.r, &self.q2);
                ell(&mut self.f, &coeff, &self.proof_a);

                self.step += 1;
                VerifyStage::MillerFinalize(self)
            }
            4 => {
                let pvk = proof_type.verifying_key();
                let index = pvk.gamma_g2_neg_pc.len() - 1;
                ell(&mut self.f, &pvk.gamma_g2_neg_pc[index], &self.prepared_input);

                self.step += 1;
                VerifyStage::MillerFinalize(self)
            }
            5 => {
                let pvk = proof_type.verifying_key();
                let index = pvk.delta_g2_neg_pc.len() - 1;
                ell(&mut self.f, &pvk.delta_g2_neg_pc[index], &self.proof_c);

                VerifyStage::FinalExponentInverse1(FinalExponentCtxInverse1(self.f))
            }
            _ => unreachable!("step is always in range [0, 5]"),
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentCtxInverse1(pub Fqk254);

impl FinalExponentCtxInverse1 {
    pub fn process(self) -> VerifyStage {
        if self.0.is_zero() {
            return VerifyStage::Finished(false);
        }

        // Guide to Pairing-based Cryptography, Algorithm 5.19.
        // v1 = c1.square()
        let v1 = self.0.c1.square();
        let v0 = self.0.c0.square();
        let v0 = Fp12ParamsWrapper::<<BnParameters as Bn>::Fp12Params>::sub_and_mul_base_field_by_nonresidue(&v0, &v1);

        if v0.is_zero() {
            // TODO
            return VerifyStage::Finished(false);
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

            VerifyStage::FinalExponentInverse2(FinalExponentCtxInverse2 {
                s0,
                s1,
                s2,
                t6,
                v0,
                f: self.0,
            })
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentCtxInverse2 {
    s0: Fq2,
    s1: Fq2,
    s2: Fq2,
    t6: Fq2,
    v0: Fq,
    f: Fqk254,
}

impl FinalExponentCtxInverse2 {
    pub fn process(self) -> VerifyStage {
        let f2 = self.v0
            .inverse()
            .map(|v1| {
                let c0 = self.t6.c0 * &v1;
                let c1 = -(self.t6.c1 * &v1);
               
                let t6 = Fq2::new(c0, c1);
                let c0 = t6 * &self.s0;
                let c1 = t6 * &self.s1;
                let c2 = t6 * &self.s2;

                let v1 = Fq6::new(c0, c1, c2);
                let c0 = self.f.c0 * &v1;
                let c1 = -(self.f.c1 * &v1);

                Fqk254::new(c0, c1)
            })
            .unwrap();

        let mut f1 = self.f;
        f1.conjugate();

        VerifyStage::FinalExponentFrobinius(FinalExponentFrobiniusCtx {
            f1,
            f2,
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentFrobiniusCtx {
    pub f1: Fqk254,
    pub f2: Fqk254,
}

impl FinalExponentFrobiniusCtx {
    pub fn process(mut self) -> VerifyStage {
        // f2 = f^(-1);
        // r = f^(p^6 - 1)
        let mut r = self.f1 * &self.f2;

        // f2 = f^(p^6 - 1)
        self.f2 = r;
        // r = f^((p^6 - 1)(p^2))
        r.frobenius_map(2);

        // r = f^((p^6 - 1)(p^2) + (p^6 - 1))
        // r = f^((p^6 - 1)(p^2 + 1))
        r *= &self.f2;

        // Hard part follows Laura Fuentes-Castaneda et al. "Faster hashing to G2"
        // by computing:
        //
        // result = elt^(q^3 * (12*z^3 + 6z^2 + 4z - 1) +
        //               q^2 * (12*z^3 + 6z^2 + 6z) +
        //               q   * (12*z^3 + 6z^2 + 4z) +
        //               1   * (12*z^3 + 12z^2 + 6z + 1))
        // which equals
        //
        // result = elt^( 2z * ( 6z^2 + 3z + 1 ) * (q^4 - q^2 + 1)/r ).
        // let y0 = exp_by_neg_x(&r, <BnParameters as Bn>::NAF);

        VerifyStage::Finished(true)
    }
}

