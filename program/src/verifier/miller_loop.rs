use std::ops::Neg;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{One, Zero};

use crate::params::{bn::{*, Bn254Parameters as BnParameters}, verify::PreparedVerifyingKey};
use crate::bn::{BnParameters as Bn, TwistType, Field, doubling_step, addition_step, mul_by_char};
use crate::verifier::Proof;
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
enum ComputeStep {
    Step0,
    Step1,
    Step2,
    Step3,
    Step4,
    Step5,
    Step6,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoop {
    step: ComputeStep,
    ate_index: u8,
    coeff_index: u8,
    f: Box<Fqk254>, // Fqk254
    r: Box<G2HomProjective254>, // G2HomProjective254
    prepared_input: Box<G1Affine254>, // G1Affine254
    proof: Box<Proof>,
    proof_b_neg: Box<G2Affine254>,
}

impl MillerLoop {
    pub fn new(prepared_input: Box<G1Affine254>, proof: Box<Proof>) -> Self {
        let r = G2HomProjective254 {
            x: proof.b.x,
            y: proof.b.y,
            z: Fq2::one(),
        };
        let proof_b_neg = proof.b.neg();
        Self {
            step: ComputeStep::Step1,
            ate_index: 0,
            coeff_index: 0,
            f: Box::new(Fqk254::one()),
            r: Box::new(r),
            prepared_input,
            proof,
            proof_b_neg: Box::new(proof_b_neg),
        }
    }

    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let ate_loop_count_inv = <BnParameters as Bn>::ATE_LOOP_COUNT_INV;

        const MAX_UNITS: usize = 1350000;
        let mut used_units = 0;
        loop {
            match self.step {
                ComputeStep::Step0 => {
                    if used_units + 100000 >= MAX_UNITS {
                        break;
                    }
                    self.f.square_in_place();
                    used_units += 100000;
                    self.step = ComputeStep::Step1;
                }
                ComputeStep::Step1 => {
                    if !self.proof.a.is_zero() && !self.proof.b.is_zero() {
                        if used_units + 155000 >= MAX_UNITS {
                            break;
                        }
                        let coeff = doubling_step(&mut self.r, FQ_TWO_INV);
                        ell(&mut self.f, &coeff, &self.proof.a);
                        used_units += 155000;
                    }
                    self.step = ComputeStep::Step2
                }
                ComputeStep::Step2 => {
                    if !self.prepared_input.is_zero() && !pvk.gamma_g2_neg_pc.is_zero() {
                        if used_units + 90000 >= MAX_UNITS {
                            break;
                        }
                        ell(&mut self.f, &pvk.gamma_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.prepared_input);
                        used_units += 90000;
                    }
                    self.step = ComputeStep::Step3;
                }
                ComputeStep::Step3 => {
                    if !self.proof.c.is_zero() && !pvk.delta_g2_neg_pc.is_zero() {
                        if used_units + 90000 >= MAX_UNITS {
                            break;
                        }
                        ell(&mut self.f, &pvk.delta_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.proof.c);
                        self.coeff_index += 1;
                        used_units += 90000;
                    }
                    self.step = ComputeStep::Step4;
                }
                ComputeStep::Step4 => {
                    let bit = ate_loop_count_inv[self.ate_index as usize];
                    match bit {
                        1 => {
                            if !self.proof.a.is_zero() && !self.proof.b.is_zero() {
                                if used_units + 155000 >= MAX_UNITS {
                                    break;
                                }
                                let coeff = addition_step(&mut self.r, &self.proof.b);
                                ell(&mut self.f, &coeff, &self.proof.a);
                                used_units += 155000;
                            }
                            self.step = ComputeStep::Step5;
                        },
                        -1 => {
                            if !self.proof.a.is_zero() && !self.proof.b.is_zero() {
                                if used_units + 155000 >= MAX_UNITS {
                                    break;
                                }
                                let coeff = addition_step(&mut self.r, &self.proof_b_neg);
                                ell(&mut self.f, &coeff, &self.proof.a);
                                used_units += 155000;
                            }
                            self.step = ComputeStep::Step5;
                        },
                        _ => {
                            if (self.ate_index as usize) >= ate_loop_count_inv.len() - 1 {
                                // in Finalize
                                return Program::MillerLoopFinalize(MillerLoopFinalize {
                                    coeff_index: self.coeff_index,
                                    prepared_input: self.prepared_input,
                                    r: self.r,
                                    f: self.f,
                                    proof: self.proof,
                                });
                            } else {
                                self.step = ComputeStep::Step0;
                            }
                        },
                    };
                    self.ate_index += 1;
                }
                ComputeStep::Step5 => {
                    if !self.prepared_input.is_zero() && !pvk.gamma_g2_neg_pc.is_zero() {
                        if used_units + 90000 >= MAX_UNITS {
                            break;
                        }
                        ell(&mut self.f, &pvk.gamma_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.prepared_input);
                        used_units += 90000;
                    }
                    self.step = ComputeStep::Step6;
                }
                ComputeStep::Step6 => {
                    if !self.proof.c.is_zero() && !pvk.delta_g2_neg_pc.is_zero() {
                        if used_units + 90000 >= MAX_UNITS {
                            break;
                        }
                        ell(&mut self.f, &pvk.delta_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.proof.c);
                        self.coeff_index += 1;
                        used_units += 90000;
                    }

                    if (self.ate_index as usize) >= ate_loop_count_inv.len() - 1 {
                        // in Finalize
                        return Program::MillerLoopFinalize(MillerLoopFinalize {
                            coeff_index: self.coeff_index,
                            prepared_input: self.prepared_input,
                            r: self.r,
                            f: self.f,
                            proof: self.proof,
                        });
                    } else {
                        self.step = ComputeStep::Step0;
                    }
                }
            }
        }
        // next loop
        Program::MillerLoop(self)
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MillerLoopFinalize {
    coeff_index: u8,
    prepared_input: Box<G1Affine254>,
    r: Box<G2HomProjective254>,
    f: Box<Fqk254>,
    proof: Box<Proof>,
}

impl MillerLoopFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let q1 = mul_by_char::<BnParameters>(self.proof.b);
        let mut q2 = mul_by_char::<BnParameters>(q1);

        if <BnParameters as Bn>::X_IS_NEGATIVE {
            self.r.y = -self.r.y;
            self.f.conjugate();
        }

        q2.y = -q2.y;

        if !self.proof.a.is_zero() && !self.proof.b.is_zero() {
            let coeff = addition_step(&mut self.r, &q1);
            ell(&mut self.f, &coeff, &self.proof.a);
        }
        if !self.prepared_input.is_zero() && !pvk.gamma_g2_neg_pc.is_zero() {
            ell(&mut self.f, &pvk.gamma_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.prepared_input);
        }
        if !self.proof.c.is_zero() && !pvk.delta_g2_neg_pc.is_zero() {
            ell(&mut self.f, &pvk.delta_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.proof.c);
        }
        self.coeff_index += 1;

        if !self.proof.a.is_zero() && !self.proof.b.is_zero() {
            let coeff = addition_step(&mut self.r, &q2);
            ell(&mut self.f, &coeff, &self.proof.a);
        }
        if !self.prepared_input.is_zero() && !pvk.gamma_g2_neg_pc.is_zero() {
            ell(&mut self.f, &pvk.gamma_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.prepared_input);
        }
        if !self.proof.c.is_zero() && !pvk.delta_g2_neg_pc.is_zero() {
            ell(&mut self.f, &pvk.delta_g2_neg_pc.ell_coeffs[self.coeff_index as usize], &self.proof.c);
        }

        Program::FinalExponentEasyPart(FinalExponentEasyPart::new(self.f))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;
    use num_traits::One;

    use crate::params::{bn::*, verify::{PreparedVerifyingKey, ProofType}};
    use crate::verifier::{Proof, program::Program};
    use crate::bn::BigInteger256 as BigInteger;
    use super::{MillerLoop, ComputeStep};

    const PVK: &PreparedVerifyingKey = ProofType::Deposit.pvk();

    fn get_proof_data() -> Proof {
        let a = G1Affine254::new_const(
            Fq::new(BigInteger::new([3750417186220724512, 3978078781434640716, 15163791108043952614, 2453596515077279990])),
            Fq::new(BigInteger::new([5354853820532153524, 8883007908664368954, 470161243035897903, 1359038641147964963])),
            false
        );
        let b = G2Affine254::new_const(
            Fq2::new_const(
                Fq::new(BigInteger::new([12118601996045181130, 896706683785346415, 4709517509465227924, 1819241630933245065])),
                Fq::new(BigInteger::new([16349181015735361827, 4843110160248729036, 17714835083434401718, 2754712195795085383])),
            ),
            Fq2::new_const(
                Fq::new(BigInteger::new([3167422245359854874, 15117403505212976980, 14561078193533486427, 992932037830603307])),
                Fq::new(BigInteger::new([10453996433908490996, 4951364747808814581, 1077088453432665796, 3244165116791247838])),
            ),
            false
        );
        let c = G1Affine254::new_const(
            Fq::new(BigInteger::new([6745960168647187300, 7304089792560402287, 5467772039812183716, 1531927553351135845])),
            Fq::new(BigInteger::new([2914263778726088111, 9472631376659388131, 16215105594981982902, 939471742250680668])),
            false
        );

        Proof { a, b, c }
    }

    fn get_deposit_verifying_program(proof: Proof) -> (G1Affine254, Program) {
        let proof_b_neg = proof.b.neg();

        let r = G2HomProjective254 {
            x: proof.b.x,
            y: proof.b.y,
            z: Fq2::one(),
        };
        let prepared_input = G1Affine254::new(
            Fq::new(BigInteger::new([15366109605146242524, 8248000168982217248, 10784397664560829633, 3448109755660551539])),
            Fq::new(BigInteger::new([10288887847322244487, 17147661464723726713, 11641908225792268002, 290404619346461690])),
            false
        );

        (prepared_input.clone(), Program::MillerLoop(MillerLoop {
            step: ComputeStep::Step0,
            ate_index: 0,
            coeff_index: 0,
            f: Box::new(Fqk254::one()),
            r: Box::new(r),
            prepared_input: Box::new(prepared_input),
            proof: Box::new(proof),
            proof_b_neg: Box::new(proof_b_neg),
        }))
    }

    fn transform_biginteger(i: BigInteger) -> ark_ff::BigInteger256 {
        use ark_ff::BigInteger256;
        BigInteger256::new(i.0)
    }

    fn transform_g1_affine(g: &G1Affine254) -> ark_bn254::G1Affine {
        use ark_bn254::{Fq, G1Affine};

        G1Affine::new(
            Fq::new(transform_biginteger(g.x.0)),
            Fq::new(transform_biginteger(g.y.0)),
            g.infinity,
        )
    }

    fn transform_g2_affine(g: &G2Affine254) -> ark_bn254::G2Affine {
        use ark_bn254::{Fq, Fq2, G2Affine};

        G2Affine::new(
            Fq2::new(
                Fq::new(transform_biginteger(g.x.c0.0)),
                Fq::new(transform_biginteger(g.x.c1.0)),
            ),
            Fq2::new(
                Fq::new(transform_biginteger(g.y.c0.0)),
                Fq::new(transform_biginteger(g.y.c1.0)),
            ),
            g.infinity,
        )
    }

    fn transform_g2_prepared(g: &G2Prepared254) -> ark_ec::bn::G2Prepared<ark_bn254::Parameters> {
        use ark_bn254::{Fq, Fq2, Parameters};
        use ark_ec::bn::G2Prepared;

        let ell_coeffs = g.ell_coeffs.iter().map(|(g1, g2, g3)| {
            (
                Fq2::new(Fq::new(transform_biginteger(g1.c0.0)), Fq::new(transform_biginteger(g1.c1.0))),
                Fq2::new(Fq::new(transform_biginteger(g2.c0.0)), Fq::new(transform_biginteger(g2.c1.0))),
                Fq2::new(Fq::new(transform_biginteger(g3.c0.0)), Fq::new(transform_biginteger(g3.c1.0))),
            )
        }).collect::<Vec<_>>();

        G2Prepared::<Parameters> {
            ell_coeffs,
            infinity: g.infinity,
        }
    }

    #[test]
    fn test_miller_loop() {
        let proof = get_proof_data();
        let (prepared_inputs, mut program) = get_deposit_verifying_program(proof.clone());

        loop {
            program = program.process(PVK);
            if let Program::FinalExponentEasyPart(_e) = &program {
                // println!("out {:?}", e.f.c0.c0.c0.0.0);
                break;
            }
        }

        {
            use ark_ec::PairingEngine;
            use ark_bn254::Bn254;

            let prepared_inputs = transform_g1_affine(&prepared_inputs);
            let proof_a = transform_g1_affine(&proof.a);
            let proof_b = transform_g2_affine(&proof.b);
            let proof_c = transform_g1_affine(&proof.c);

            let pvk_gamma_g2_neg_pc = transform_g2_prepared(&PVK.gamma_g2_neg_pc);
            let pvk_delta_g2_neg_pc = transform_g2_prepared(&PVK.delta_g2_neg_pc);

            let out = Bn254::miller_loop(
                [
                    (proof_a.into(), proof_b.into()),
                    (
                        prepared_inputs.into(),
                        pvk_gamma_g2_neg_pc,
                    ),
                    (proof_c.into(), pvk_delta_g2_neg_pc),
                ].iter()
            );

            println!("out {:?}", out);
        }
    }
}
