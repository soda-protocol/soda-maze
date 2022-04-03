use std::ops::{AddAssign, MulAssign};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::pubkey::Pubkey;

use crate::{bn::{BnParameters as Bn, BitIteratorBE, TwistType, Field, doubling_step, addition_step, mul_by_char, Fp12ParamsWrapper, QuadExtParameters, Fp6ParamsWrapper, CubicExtParameters, Fp2ParamsWrapper}, OperationType};

use super::{state::VerifyStage, params::*, context::{UpdateContext, ReadOnlyContext, InitializeContext}};
use super::params::{Fr, Bn254Parameters as BnParameters};

// type UpdateContext<'a, S> = (&'a Pubkey, &'a mut Option<&'a mut S>);
// type ReadOnlyContext<'a, S> = (&'a Pubkey, &'a mut Option<&'a S>);
// type InitializeContext<'a, S> = (&'a Pubkey, &'a mut Option<S>);

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
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u8,
    pub g_ic: Pubkey, // G1Projective254
    pub tmp: Pubkey, // G1Projective254
}

impl PrepareInputs {
    pub fn process(
        mut self,
        proof_type: OperationType,
        public_inputs: &[Fr],
        g_ic_ctx: &UpdateContext<G1Projective254>,
        tmp_ctx: &UpdateContext<G1Projective254>,
    ) -> VerifyStage {
        let mut g_ic = g_ic_ctx.borrow_mut();
        let mut tmp = tmp_ctx.borrow_mut();

        let public_input = public_inputs[self.input_index as usize];
        let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();
    
        const MAX_COMPRESS_CYCLE: usize = 4;

        let pvk = proof_type.verifying_key();
        BitIteratorBE::new(public_input)
            .skip_while(|b| !b)
            .skip(self.bit_index as usize)
            .take(MAX_COMPRESS_CYCLE)
            .for_each(|bit| {
                tmp.double_in_place();
                if bit {
                    tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
            });
        
        self.bit_index += MAX_COMPRESS_CYCLE as u8;
        if self.bit_index as usize >= bits.len() {
            g_ic.add_assign(*tmp);
            self.input_index += 1;
            if public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;
                **tmp = G1Projective254::zero();
                **g_ic = *pvk.g_ic_init;
    
                VerifyStage::PrepareInputs(self)
            } else {
                tmp_ctx.close();
                VerifyStage::FinalizeInputs(FinalizeInputs {
                    g_ic: self.g_ic,
                })
            }
        } else {
            VerifyStage::PrepareInputs(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalizeInputs {
    pub g_ic: Pubkey, // G1Projective254
}

impl FinalizeInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        g_ic_ctx: &ReadOnlyContext<G1Projective254>,
        proof_a_ctx: &ReadOnlyContext<G1Affine254>,
        proof_b_ctx: &ReadOnlyContext<G2Affine254>,
        proof_c_ctx: &ReadOnlyContext<G1Affine254>,
        r_ctx: &InitializeContext<G2HomProjective254>,
        f_ctx: &InitializeContext<Fqk254>,
        prepared_input_ctx: &InitializeContext<G1Affine254>,
    ) -> VerifyStage {
        let g_ic = g_ic_ctx.as_ref();
        let proof_b = proof_b_ctx.as_ref();

        let r = G2HomProjective254 {
            x: proof_b.x,
            y: proof_b.y,
            z: Fq2::one(),
        };
        let f = Fqk254::one();

        let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;
        r_ctx.fill_with(r);
        f_ctx.fill_with(f);
        prepared_input_ctx.fill_with(G1Affine254::from(*g_ic));
        g_ic_ctx.close();
        VerifyStage::MillerLoop(MillerLoop {
            step: 1,
            index,
            coeff_index: 0,
            prepared_input: prepared_input_ctx.pubkey(),
            proof_a: proof_a_ctx.pubkey(),
            proof_b: proof_b_ctx.pubkey(),
            proof_c: proof_c_ctx.pubkey(),
            r: r_ctx.pubkey(),
            f: f_ctx.pubkey(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoop {
    pub step: u8,
    pub index: u8,
    pub coeff_index: u8,
    pub f: Pubkey, // Fqk254
    pub r: Pubkey, // G2HomProjective254
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_a: Pubkey, // G1Affine254
    pub proof_b: Pubkey, // G2Affine254
    pub proof_c: Pubkey, // G1Affine254
}

impl MillerLoop {
    pub fn process_0(
        mut self,
        f_ctx: &UpdateContext<Fqk254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();

        f.square_in_place();
        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    pub fn process_1(
        mut self,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        proof_a_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let mut r = r_ctx.borrow_mut();
        let proof_a = proof_a_ctx.as_ref();

        let coeff = doubling_step(*r, FQ_TWO_INV);
        ell(*f, &coeff, proof_a);
    
        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    pub fn process_2(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        prepared_input_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let prepared_input = prepared_input_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        ell(*f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], prepared_input);
    
        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_3(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        proof_b_ctx: &ReadOnlyContext<G2Affine254>,
        proof_c_ctx: &ReadOnlyContext<G1Affine254>,
        q1_ctx: &InitializeContext<G2Affine254>,
        q2_ctx: &InitializeContext<G2Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let proof_c = proof_c_ctx.as_ref();
        let proof_b = proof_b_ctx.as_ref();
        let mut r = r_ctx.borrow_mut();

        let pvk = proof_type.verifying_key();
        ell(*f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], proof_c);

        self.index -= 1;
        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        if bit == 0 {
            if self.index == 0 {
                let q1 = mul_by_char::<BnParameters>(*proof_b);
                let mut q2 = mul_by_char::<BnParameters>(q1);

                if <BnParameters as Bn>::X_IS_NEGATIVE {
                    r.y = -r.y;
                    f.conjugate();
                }

                q2.y = -q2.y;

                q1_ctx.fill_with(q1);
                q2_ctx.fill_with(q2);
                proof_b_ctx.close();
                return VerifyStage::MillerFinalize(MillerFinalize {
                    step: 0,
                    prepared_input: self.prepared_input,
                    proof_a: self.proof_a,
                    proof_c: self.proof_c,
                    q1: q1_ctx.pubkey(),
                    q2: q2_ctx.pubkey(),
                    r: self.r,
                    f: self.f,
                });
            }
        }

        self.coeff_index += 1;
        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    pub fn process_4(
        mut self,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        proof_a_ctx: &ReadOnlyContext<G1Affine254>,
        proof_b_ctx: &ReadOnlyContext<G2Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let mut r = r_ctx.borrow_mut();
        let proof_a = proof_a_ctx.as_ref();
        let proof_b = proof_b_ctx.as_ref();

        let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[self.index as usize];
        let coeff = match bit {
            1 => addition_step(*r, proof_b),
            -1 => {
                let neg_b = -(*proof_b);
                addition_step(*r, &neg_b)
            }
            _ => unreachable!("bit is always be 1 or -1 at hear"),
        };
        ell(*f, &coeff, proof_a);

        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    pub fn process_5(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        prepared_input_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let prepared_input = prepared_input_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        ell(*f, &pvk.gamma_g2_neg_pc[self.coeff_index as usize], prepared_input);

        self.step += 1;
        VerifyStage::MillerLoop(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_6(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        proof_b_ctx: &ReadOnlyContext<G2Affine254>,
        prepared_input_ctx: &ReadOnlyContext<G1Affine254>,
        q1_ctx: &InitializeContext<G2Affine254>,
        q2_ctx: &InitializeContext<G2Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let mut r = r_ctx.borrow_mut();
        let proof_b = proof_b_ctx.as_ref();
        let prepared_input = prepared_input_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        ell(*f, &pvk.delta_g2_neg_pc[self.coeff_index as usize], prepared_input);

        if self.index == 0 {
            let q1 = mul_by_char::<BnParameters>(*proof_b);
            let mut q2 = mul_by_char::<BnParameters>(q1);

            if <BnParameters as Bn>::X_IS_NEGATIVE {
                r.y = -r.y;
                f.conjugate();
            }

            q2.y = -q2.y;

            q1_ctx.fill_with(q1);
            q2_ctx.fill_with(q2);
            proof_b_ctx.close();
            return VerifyStage::MillerFinalize(MillerFinalize {
                step: 0,
                prepared_input: self.prepared_input,
                proof_a: self.proof_a,
                proof_c: self.proof_c,
                q1: q1_ctx.pubkey(),
                q2: q2_ctx.pubkey(),
                r: self.r,
                f: self.f,
            });
        } else {
            self.coeff_index += 1;
            self.step = 0;
            VerifyStage::MillerLoop(self)
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerFinalize {
    pub step: u8,
    pub prepared_input: Pubkey, // G1Affine254
    pub proof_a: Pubkey, // G1Affine254
    pub proof_c: Pubkey, // G1Affine254
    pub q1: Pubkey, // G2Affine254
    pub q2: Pubkey, // G2Affine254
    pub r: Pubkey, // G2HomProjective254
    pub f: Pubkey, // Fqk254
}

impl MillerFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process_0(
        mut self,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        q1_ctx: &ReadOnlyContext<G2Affine254>,
        proof_a_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let mut r = r_ctx.borrow_mut();
        let q1 = q1_ctx.as_ref();
        let proof_a = proof_a_ctx.as_ref();

        let coeff = addition_step(*r, q1);
        ell(*f, &coeff, proof_a);

        self.step += 1;
        q1_ctx.close();
        VerifyStage::MillerFinalize(self)
    }

    pub fn process_1(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        prepared_input_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let prepared_input = prepared_input_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        let index = pvk.gamma_g2_neg_pc.len() - 2;
        ell(*f, &pvk.gamma_g2_neg_pc[index], prepared_input);

        self.step += 1;
        VerifyStage::MillerFinalize(self)
    }

    pub fn process_2(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        proof_c_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let proof_c = proof_c_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        let index = pvk.delta_g2_neg_pc.len() - 2;
        ell(*f, &pvk.delta_g2_neg_pc[index], proof_c);


        self.step += 1;
        VerifyStage::MillerFinalize(self) 
    }

    pub fn process_3(
        mut self,
        f_ctx: &UpdateContext<Fqk254>,
        r_ctx: &UpdateContext<G2HomProjective254>,
        q2_ctx: &ReadOnlyContext<G2Affine254>,
        proof_a_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let mut r = r_ctx.borrow_mut();
        let q2 = q2_ctx.as_ref();
        let proof_a = proof_a_ctx.as_ref();

        let coeff = addition_step(*r, q2);
        ell(*f, &coeff, proof_a);

        self.step += 1;
        r_ctx.close();
        q2_ctx.close();
        proof_a_ctx.close();
        VerifyStage::MillerFinalize(self)
    }

    pub fn process_4(
        mut self,
        proof_type: OperationType,
        f_ctx: &UpdateContext<Fqk254>,
        prepared_input_ctx: &ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let prepared_input = prepared_input_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        let index = pvk.gamma_g2_neg_pc.len() - 1;
        ell(*f, &pvk.gamma_g2_neg_pc[index], prepared_input);

        self.step += 1;
        prepared_input_ctx.close();
        VerifyStage::MillerFinalize(self)
    }

    pub fn process_5(
        self,
        proof_type: OperationType,
        f_ctx: UpdateContext<Fqk254>,
        proof_c_ctx: ReadOnlyContext<G1Affine254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let proof_c = proof_c_ctx.as_ref();

        let pvk = proof_type.verifying_key();
        let index = pvk.delta_g2_neg_pc.len() - 1;
        ell(*f, &pvk.delta_g2_neg_pc[index], proof_c);
        
        proof_c_ctx.close();
        VerifyStage::FinalExponentInverse0(FinalExponentInverse0 {
            f: self.f,
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentInverse0 {
    f: Pubkey, // Fqk254
}

impl FinalExponentInverse0 {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        f_ctx: &ReadOnlyContext<Fqk254>,
        s0_ctx: &InitializeContext<Fq2>,
        s1_ctx: &InitializeContext<Fq2>,
        s2_ctx: &InitializeContext<Fq2>,
        t6_ctx: &InitializeContext<Fq2>,
        v0_ctx: &InitializeContext<Fq>,
    ) -> VerifyStage {
        let f = f_ctx.as_ref();

        if f.is_zero() {
            return VerifyStage::Finished(false);
        }

        // Guide to Pairing-based Cryptography, Algorithm 5.19.
        // v1 = c1.square()
        let v1 = f.c1.square();
        let v0 = f.c0.square();
        let v0 = Fp12ParamsWrapper::<<BnParameters as Bn>::Fp12Params>::sub_and_mul_base_field_by_nonresidue(&v0, &v1);

        if v0.is_zero() {
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

            s0_ctx.fill_with(s0);
            s1_ctx.fill_with(s1);
            s2_ctx.fill_with(s2);
            t6_ctx.fill_with(t6);
            v0_ctx.fill_with(v0);
            VerifyStage::FinalExponentInverse1(FinalExponentInverse1 {
                f: self.f,
                s0: s0_ctx.pubkey(),
                s1: s1_ctx.pubkey(),
                s2: s2_ctx.pubkey(),
                t6: t6_ctx.pubkey(),
                v0: v0_ctx.pubkey(),
            })
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentInverse1 {
    f: Pubkey, // Fqk254
    s0: Pubkey, // Fp2
    s1: Pubkey, // Fp2
    s2: Pubkey, // Fp2
    t6: Pubkey, // Fp2
    v0: Pubkey, // Fp
}

impl FinalExponentInverse1 {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        f_ctx: &UpdateContext<Fqk254>,
        s0_ctx: &ReadOnlyContext<Fq2>,
        s1_ctx: &ReadOnlyContext<Fq2>,
        s2_ctx: &ReadOnlyContext<Fq2>,
        t6_ctx: &ReadOnlyContext<Fq2>,
        v0_ctx: &ReadOnlyContext<Fq>,
        f2_ctx: &InitializeContext<Fqk254>,
    ) -> VerifyStage {
        let mut f = f_ctx.borrow_mut();
        let s0 = s0_ctx.as_ref();
        let s1 = s1_ctx.as_ref();
        let s2 = s2_ctx.as_ref();
        let t6 = t6_ctx.as_ref();
        let v0 = v0_ctx.as_ref();

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

        f2_ctx.fill_with(f2);
        s0_ctx.close();
        s1_ctx.close();
        s2_ctx.close();
        t6_ctx.close();
        v0_ctx.close();
        VerifyStage::FinalExponentStep0(FinalExponentStep0 {
            step: 0,
            f1: self.f,
            f2: f2_ctx.pubkey(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep0 {
    pub step: u8,
    pub f1: Pubkey, // Fqk254 
    pub f2: Pubkey, // Fqk254
}

impl FinalExponentStep0 {
    pub fn process_0(
        mut self,
        f1_ctx: &UpdateContext<Fqk254>,
        f2_ctx: &UpdateContext<Fqk254>,
    ) -> VerifyStage {
        let mut f1 = f1_ctx.borrow_mut();
        let mut f2 = f2_ctx.borrow_mut();

        // f2 = f^(-1);
        // r = f^(p^6 - 1)
        f1.mul_assign(**f2);

        // f2 = f^(p^6 - 1)
        **f2 = **f1;

        // r = f^((p^6 - 1)(p^2))
        f1.frobenius_map(2);

        self.step += 1;
        VerifyStage::FinalExponentStep0(self)
    }

    pub fn process_1(
        self,
        f1_ctx: &UpdateContext<Fqk254>,
        f2_ctx: &ReadOnlyContext<Fqk254>,
        y0_ctx: &InitializeContext<Fqk254>,
    ) -> VerifyStage {
        let mut f1 = f1_ctx.borrow_mut();
        let f2 = f2_ctx.as_ref();

        f1.mul_assign(f2);

        y0_ctx.fill_with(Fqk254::one());
        f2_ctx.close();
        VerifyStage::FinalExponentStep1(FinalExponentStep1 {
            step: 1,
            index: 0,
            y0: y0_ctx.pubkey(),
            r: self.f1,
        })
    }
}

macro_rules! exp_by_neg_x {
    ($name:ident, $stage:ident) => {
        impl $name {
            pub fn process_0(
                mut self,
                res_ctx: &UpdateContext<Fqk254>,
            ) -> VerifyStage {
                let mut res = res_ctx.borrow_mut();

                res.square_in_place();
        
                self.step += 1;
                VerifyStage::$stage(self)
            }

            fn process_1_inner(
                mut self,
                f_ctx: &ReadOnlyContext<Fqk254>,
                res_ctx: &UpdateContext<Fqk254>,
            ) -> (Self, bool) {
                let mut res = res_ctx.borrow_mut();
                let f = f_ctx.as_ref();

                let naf = <BnParameters as Bn>::NAF;
                let value = naf[self.index as usize];
                self.index += 1;

                if value != 0 {
                    self.step = 0;
        
                    if value > 0 {
                        res.mul_assign(f);
                    } else {
                        let mut f_inv = f.clone();
                        f_inv.conjugate();
                        res.mul_assign(f_inv);
                    }
                }

                if (self.index as usize) < naf.len() {
                    (self, true)
                } else {
                    if !<BnParameters as Bn>::X_IS_NEGATIVE {
                        res.conjugate();
                    }
        
                    (self, false)
                }
            }
        }
    };
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep1 {
    pub step: u8,
    pub index: u8,
    pub y0: Pubkey, // Fqk254
    pub r: Pubkey, // Fqk254
}

impl FinalExponentStep1 {
    pub fn process_1(
        self,
        r_ctx: &ReadOnlyContext<Fqk254>,
        y0_ctx: &UpdateContext<Fqk254>,
    ) -> VerifyStage {
        let (s, is_self) = self.process_1_inner(r_ctx, y0_ctx);
        if is_self {
            VerifyStage::FinalExponentStep1(s)
        } else {
            VerifyStage::FinalExponentStep2(FinalExponentStep2 {
                r: s.r,
                y0: s.y0,
            })
        }
    }
}

exp_by_neg_x!(FinalExponentStep1, FinalExponentStep1);

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep2 {
    pub r: Pubkey, // Fqk254
    pub y0: Pubkey, // Fqk254
}

impl FinalExponentStep2 {
    pub fn process(
        self,
        y0_ctx: &ReadOnlyContext<Fqk254>,
        y1_ctx: &InitializeContext<Fqk254>,
        y2_ctx: &InitializeContext<Fqk254>,
    ) -> VerifyStage {
        let y0 = y0_ctx.as_ref();

        let y1 = y0.cyclotomic_square();
        let y2 = y1.cyclotomic_square();

        y0_ctx.close();
        y1_ctx.fill_with(y1);
        y2_ctx.fill_with(y2);
        VerifyStage::FinalExponentStep3(FinalExponentStep3 {
            r: self.r,
            y1: y1_ctx.pubkey(),
            y2: y2_ctx.pubkey(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep3 {
    pub r: Pubkey, // Fqk254
    pub y1: Pubkey, // Fqk254
    pub y2: Pubkey, // Fqk254
}

impl FinalExponentStep3 {
    pub fn process(
        self,
        y1_ctx: &ReadOnlyContext<Fqk254>,
        y2_ctx: &ReadOnlyContext<Fqk254>,
        y3_ctx: &InitializeContext<Fqk254>,
        y4_ctx: &InitializeContext<Fqk254>,
    ) -> VerifyStage {
        let y1 = y1_ctx.as_ref();
        let y2 = y2_ctx.as_ref();

        let y3 = *y2 * y1;

        y2_ctx.close();
        y3_ctx.fill_with(y3);
        y4_ctx.fill_with(Fqk254::one());
        VerifyStage::FinalExponentStep4(FinalExponentStep4 {
            step: 1,
            index: 0,
            r: self.r,
            y1: self.y1,
            y3: y3_ctx.pubkey(),
            y4: y4_ctx.pubkey(),
        })
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep4 {
    pub step: u8,
    pub index: u8,
    pub r: Pubkey, // Fqk254
    pub y1: Pubkey, // Fqk254
    pub y3: Pubkey, // Fqk254
    pub y4: Pubkey, // Fqk254
}

impl FinalExponentStep4 {
    pub fn process_1(
        self,
        y3_ctx: &ReadOnlyContext<Fqk254>,
        y4_ctx: &UpdateContext<Fqk254>,
        y5_ctx: &InitializeContext<Fqk254>,
        y6_ctx: &InitializeContext<Fqk254>,
    ) -> VerifyStage {
        let (s, is_self) = self.process_1_inner(y3_ctx, y4_ctx);
        if is_self {
            VerifyStage::FinalExponentStep4(s)
        } else {
            let y5 = y4_ctx.borrow_mut().cyclotomic_square();

            y5_ctx.fill_with(y5);
            y6_ctx.fill_with(Fqk254::one());
            VerifyStage::FinalExponentStep5(FinalExponentStep5 {
                step: 1,
                index: 0,
                r: s.r,
                y1: s.y1,
                y3: s.y3,
                y4: s.y4,
                y5: y5_ctx.pubkey(),
                y6: y6_ctx.pubkey(),
            })
        }
    }
}

exp_by_neg_x!(FinalExponentStep4, FinalExponentStep4);

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep5 {
    pub step: u8,
    pub index: u8,
    pub r: Pubkey, // Fqk254
    pub y1: Pubkey, // Fqk254
    pub y3: Pubkey, // Fqk254
    pub y4: Pubkey, // Fqk254
    pub y5: Pubkey, // Fqk254
    pub y6: Pubkey, // Fqk254
}

impl FinalExponentStep5 {
    pub fn process_1(
        self,
        y3_ctx: &UpdateContext<Fqk254>,
        y5_ctx: &ReadOnlyContext<Fqk254>,
        y6_ctx: &UpdateContext<Fqk254>,
    ) -> VerifyStage {
        let (s, is_self) = self.process_1_inner(y5_ctx, y6_ctx);
        if is_self {
            VerifyStage::FinalExponentStep5(s)
        } else {
            y3_ctx.borrow_mut().conjugate();
            y6_ctx.borrow_mut().conjugate();
            
            y5_ctx.close();
            VerifyStage::FinalExponentStep6(FinalExponentStep6 {
                r: s.r,
                y1: s.y1,
                y3: s.y3,
                y4: s.y4,
                y6: s.y6,
            })
        }
    }
}

exp_by_neg_x!(FinalExponentStep5, FinalExponentStep5);

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct FinalExponentStep6 {
    pub r: Pubkey, // Fqk254
    pub y1: Pubkey, // Fqk254
    pub y3: Pubkey, // Fqk254
    pub y4: Pubkey, // Fqk254
    pub y6: Pubkey, // Fqk254
}
