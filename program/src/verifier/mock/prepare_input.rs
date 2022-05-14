use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::context::Context;
use crate::bn::{BnParameters as Bn, BitIteratorBE, FpParameters};
use crate::params::{*, Bn254Parameters as BnParameters, FrParameters};
use crate::{OperationType, error::MazeError, verifier::{ProofA, ProofB, ProofC}};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u16,
    pub public_inputs: Vec<Fr>, // Vec<Fr>
    pub g_ic: G1Projective254, // G1Projective254
    pub tmp: G1Projective254, // G1Projective254
}

impl PrepareInputs {
    pub fn process(
        mut self,
        proof_type: &OperationType,
    ) -> Result<(), ProgramError> {
        let public_input = self.public_inputs[self.input_index as usize];
        let fr_bits = <FrParameters as FpParameters>::MODULUS_BITS as usize;
        let pvk = proof_type.verifying_key();

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
            } else {
                let _c = G1Affine254::from(self.g_ic);
            }
        }

        Ok(())
    }
}
