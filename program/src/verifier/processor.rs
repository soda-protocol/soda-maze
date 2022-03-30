use std::ops::AddAssign;

use num_traits::{Zero, One};

use crate::{bn::{BnParameters as Bn, BitIteratorBE, TwistType, Field, doubling_step, addition_step}, OperationType};

use super::{state::{VerifyStage, Proof}, params::*};
use super::params::{Fr, Bn254Parameters as BnParameters};

#[inline(never)]
pub fn process_compress_inputs(
    mut input_index: u8,
    mut g_ic: G1Projective254,
    mut bit_index: u8,
    mut tmp: G1Projective254,
    public_inputs: Vec<Fr>,
    proof_type: OperationType,
) -> VerifyStage {
    let public_input = public_inputs[input_index as usize];
    let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();

    const MAX_COMPRESS_CYCLE: usize = 4;
    let start = bit_index as usize;
    let end = start + MAX_COMPRESS_CYCLE;
    let (end, finished) = if end < bits.len() {
        (end, false)
    } else {
        (bits.len(), true)
    };

    let pvk = proof_type.verifying_key();
    for bit in &bits[start..end] {
        tmp.double_in_place();
        if *bit {
            tmp.add_assign_mixed(&pvk.gamma_abc_g1[input_index as usize]);
        }
    }

    if finished {
        g_ic.add_assign(&tmp);
        input_index += 1;
        if public_inputs.get(input_index as usize).is_some() {
            bit_index = 0;
            tmp = G1Projective254::zero();
            g_ic = *pvk.g_ic_init;

            VerifyStage::CompressInputs {
                input_index,
                g_ic,
                bit_index,
                tmp,
            }
        } else {
            VerifyStage::PrepareInput {
                proof_type,
                compressed_input: g_ic,
            }
        }
    } else {
        VerifyStage::CompressInputs {
            input_index,
            g_ic,
            bit_index: end as u8,
            tmp,
        }
    }
}

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

pub fn process_prepare_input(
    compressed_input: G1Projective254,
    proof_type: OperationType,
    proof: Proof,
) -> VerifyStage {
    let prepared_input = G1Affine254::from(compressed_input);
    let rb = G2HomProjective254 {
        x: proof.b.x,
        y: proof.b.y,
        z: Fq2::one(),
    };

    let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;
    let negb = -proof.b;
    VerifyStage::MillerLoop {
        index,
        coeff_index: 0,
        proof_type,
        prepared_input,
        rb,
        negb,
        f: Fqk254::one(),
    }
}

pub fn process_miller_loop_step_1(
    proof_type: OperationType,
    proof: &Proof,
    prepared_input: G1Affine254,
    negb: G2Affine254,
    mut index: u8,
    mut coeff_index: u8,
    mut rb: G2HomProjective254,
    mut f: Fqk254,
) -> Option<VerifyStage> {
    if index as usize != <BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1 {
        f.square_in_place();
    }
    index -= 1;

    let pvk = proof_type.verifying_key();
    
    let coeff = doubling_step(&mut rb, FQ_TWO_INV);
    ell(&mut f, &coeff, &proof.a);

    ell(&mut f, &pvk.gamma_g2_neg_pc[coeff_index as usize], &prepared_input);
    ell(&mut f, &pvk.delta_g2_neg_pc[coeff_index as usize], &proof.c);
    coeff_index += 1;

    let bit = <BnParameters as Bn>::ATE_LOOP_COUNT[index as usize];
    match bit {
        1 => {
            let coeff = addition_step(&mut rb, &proof.b);
            ell(&mut f, &coeff, &proof.a);

            ell(&mut f, &pvk.gamma_g2_neg_pc[coeff_index as usize], &prepared_input);
            ell(&mut f, &pvk.delta_g2_neg_pc[coeff_index as usize], &proof.c);
            coeff_index += 1;
        }
        -1 => {
            let coeff = addition_step(&mut rb, &negb);
            ell(&mut f, &coeff, &proof.a);

            ell(&mut f, &pvk.gamma_g2_neg_pc[coeff_index as usize], &prepared_input);
            ell(&mut f, &pvk.delta_g2_neg_pc[coeff_index as usize], &proof.c);
            coeff_index += 1;
        }
        _ => {}
    }

    if index == 0 {
        None
    } else {
        Some(VerifyStage::MillerLoop {
            index,
            coeff_index,
            proof_type,
            prepared_input,
            rb,
            negb,
            f,
        })
    }
}

