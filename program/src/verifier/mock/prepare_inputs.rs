use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};

use crate::bn::{BnParameters as Bn, BitIteratorBE, FpParameters};
use crate::params::{bn::{*, Bn254Parameters as BnParameters}, proof::PreparedVerifyingKey};
use crate::verifier::{ProofA, ProofB, ProofC};
use super::program::Program;
use super::miller_loop::MillerLoop;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u16,
    pub public_inputs: Box<Vec<Fr>>,
    pub g_ic: G1Projective254,
    pub tmp: G1Projective254,
    pub proof_a: ProofA,
    pub proof_b: ProofB,
    pub proof_c: ProofC,
}

impl PrepareInputs {
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let public_input = self.public_inputs[self.input_index as usize];
        let fr_bits = <FrParameters as FpParameters>::MODULUS_BITS as usize;

        const MAX_LOOP: usize = 40;
        BitIteratorBE::new(public_input)
            .skip(256 - fr_bits)
            .skip(self.bit_index as usize)
            .take(MAX_LOOP)
            .for_each(|bit| {
                self.tmp.double_in_place();
                if bit {
                    self.tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
                self.bit_index += 1;
            });
        
        if self.bit_index as usize >= fr_bits {
            self.g_ic.add_assign(&self.tmp);
            self.input_index += 1;
            
            if self.public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;
                self.tmp = G1Projective254::zero();

                Program::PrepareInputs(self)
            } else {
                let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;
                let r = G2HomProjective254 {
                    x: self.proof_b.x,
                    y: self.proof_b.y,
                    z: Fq2::one(),
                };
                let f = Fqk254::one();
                let prepared_input = G1Affine254::from(self.g_ic);

                Program::MillerLoop(MillerLoop {
                    index,
                    coeff_index: 0,
                    f,
                    r,
                    prepared_input,
                    proof_a: self.proof_a,
                    proof_b: self.proof_b,
                    proof_c: self.proof_c,
                })
            }
        } else {
            Program::PrepareInputs(self)
        }
    }
}
