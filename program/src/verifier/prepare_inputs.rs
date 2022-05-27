use std::ops::{AddAssign, Neg};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};

use crate::bn::{BigInteger256 as BigInteger, BitIteratorBE};
use crate::params::bn::{G1Projective254, G1Affine254, G2HomProjective254, Fq2, Fqk254};
use crate::params::proof::PreparedVerifyingKey;
use crate::verifier::{ProofA, ProofB, ProofC};
use super::program::Program;
use super::miller_loop::MillerLoop;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u16,
    pub public_inputs: Box<Vec<BigInteger>>,
    pub g_ic: Box<G1Projective254>,
    pub tmp: Box<G1Projective254>,
    pub proof_a: Box<ProofA>,
    pub proof_b: Box<ProofB>,
    pub proof_c: Box<ProofC>,
}

impl PrepareInputs {
    pub fn process(mut self, pvk: &PreparedVerifyingKey) -> Program {
        let mut public_input = self.public_inputs[self.input_index as usize];
        let mut bits_iter = BitIteratorBE::without_leading_zeros(public_input)
            .skip(self.bit_index as usize);

        const MAX_UINTS: usize = 1350000;
        let mut used_units = 0;
        loop {
            if let Some(bit) = bits_iter.next() {
                self.tmp.double_in_place();
                used_units += 500;
                if bit {
                    self.tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                    used_units += 42000;
                }
                self.bit_index += 1;
            } else {
                self.g_ic.add_assign(&self.tmp);
                self.input_index += 1;
                used_units += 500;

                if self.input_index as usize >= self.public_inputs.len() {
                    let r = G2HomProjective254 {
                        x: self.proof_b.x,
                        y: self.proof_b.y,
                        z: Fq2::one(),
                    };
                    let prepared_input = G1Affine254::from(*self.g_ic);
                    let proof_b_neg = self.proof_b.neg();
    
                    return Program::MillerLoop(MillerLoop {
                        ate_index: 0,
                        coeff_index: 0,
                        f: Box::new(Fqk254::one()),
                        r: Box::new(r),
                        prepared_input: Box::new(prepared_input),
                        proof_a: self.proof_a,
                        proof_b: self.proof_b,
                        proof_b_neg: Box::new(proof_b_neg),
                        proof_c: self.proof_c,
                    });
                } else {
                    self.bit_index = 0;
                    self.tmp = Box::new(G1Projective254::zero());

                    public_input = self.public_inputs[self.input_index as usize];
                    bits_iter = BitIteratorBE::without_leading_zeros(public_input).skip(0);
                    used_units += 500;
                }
            }

            if used_units >= MAX_UINTS {
                break;
            }
        }

        Program::PrepareInputs(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::{params::{bn::{G1Affine254, G2Affine254, G1Projective254}, proof::{PreparedVerifyingKey, ProofType}}, verifier::{ProofA, ProofB, ProofC, program::Program}};
    use crate::params::bn::{Fq, Fq2};
    use crate::bn::BigInteger256 as BigInteger;

    use super::PrepareInputs;

    const PROOF_A: ProofA = G1Affine254::new_const(
        Fq::new(BigInteger::new([14715620368662735844, 9563436648438579353, 9817845158629706665, 2420889558595263392])),
        Fq::new(BigInteger::new([8640892419674201321, 14834230856296141528, 4198848546444402927, 1517119377864516134])),
        false,
    );
    
    const PROOF_B: ProofB = G2Affine254::new_const(
        Fq2::new_const(
            Fq::new(BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545])),
            Fq::new(BigInteger::new([4791893780199645830, 13020716387556337386, 12915032691238673322, 2866902253618994548])),
        ),
        Fq2::new_const(
            Fq::new(BigInteger::new([2204364260910044889, 4961323307537146896, 3192016866730518327, 1801533657434404900])),
            Fq::new(BigInteger::new([13208303890985533178, 12442437710149681723, 9219358705006067983, 3191371954673554778])),
        ),
        false,
    );
    
    const PROOF_C: ProofC = G1Affine254::new_const(
        Fq::new(BigInteger::new([5823303549099682051, 11298647609364880259, 17539675314511186284, 556302735522023958])),
        Fq::new(BigInteger::new([2083577888616351182, 10916945937534065039, 1520021691683278293, 2748969749429754277])),
        false,
    );

    const G1_PROJECTIVE_VALUE: G1Projective254 = G1Projective254::new_const(
        Fq::new(BigInteger::new([8702585202244274910, 9214718725403065568, 17690655619678158896, 1222195394398354666])),
        Fq::new(BigInteger::new([3439699351422384141, 18051431940401055444, 13194437363659758174, 2607686238957372954])),
        Fq::new(BigInteger::new([15230403791020821917, 754611498739239741, 7381016538464732716, 1011752739694698287])),
    );

    const PREPARE_INPUT: BigInteger = BigInteger::new([14384816041077872766, 431448166635449345, 6321897284235301150, 2191027455511027545]);

    const PVK: &PreparedVerifyingKey = ProofType::Deposit.pvk();

    #[test]
    fn test_prepare_inputs() {
        let prepare_inputs = PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs: Box::new(vec![PREPARE_INPUT]),
            g_ic: Box::new(G1_PROJECTIVE_VALUE),
            tmp: Box::new(G1_PROJECTIVE_VALUE),
            proof_a: Box::new(PROOF_A),
            proof_b: Box::new(PROOF_B),
            proof_c: Box::new(PROOF_C),
        };

        let program = prepare_inputs.process(PVK);

        match program {
            Program::PrepareInputs(pi) => {
                println!("{:?}", pi.bit_index);
            }
            Program::MillerLoop(mi) => {
                println!("{:?}", mi.coeff_index);
            }
            _ => unreachable!(),
        }
    }
}