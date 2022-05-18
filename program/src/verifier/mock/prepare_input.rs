use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_error::ProgramError;

use crate::bn::{BitIteratorBE, FpParameters};
use crate::params::bn::*;
use crate::params::vk::get_prepared_verifying_key;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u16,
    pub public_inputs: Box<Vec<Fr>>, // Vec<Fr>
    pub g_ic: G1Projective254, // G1Projective254
    pub tmp: G1Projective254, // G1Projective254
}

impl PrepareInputs {
    pub fn process(mut self) -> Result<(), ProgramError> {
        let pvk = get_prepared_verifying_key();

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
            } else {
                let _c = G1Affine254::from(self.g_ic);
            }
        }

        Ok(())
    }
}
