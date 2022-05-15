use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::context::{Context512, Context2048};
use crate::bn::{BnParameters as Bn, BitIteratorBE, FpParameters};
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::{ProofType, error::MazeError, verifier::ProofB};

use super::fsm::FSM;
use super::miller_loop::MillerLoop;

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u8,
    pub public_inputs: Pubkey, // Vec<Fr>
    pub g_ic: Pubkey, // G1Projective254
    pub tmp: Pubkey, // G1Projective254
    pub proof_ac: Pubkey, // ProofA and ProofC
    pub proof_b: Pubkey, // ProofB
}

impl PrepareInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        mut self,
        proof_type: &ProofType,
        public_inputs_ctx: &Context2048<Box<Vec<Fr>>>,
        proof_b_ctx: &Context512<ProofB>,
        g_ic_ctx: &Context512<G1Projective254>,
        tmp_ctx: &Context512<G1Projective254>,
        prepared_input_ctx: &Context512<G1Affine254>,
        r_ctx: &Context512<G2HomProjective254>,
        f_ctx: &Context512<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if g_ic_ctx.pubkey() != &self.g_ic {
            msg!("g_ic_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if tmp_ctx.pubkey() != &self.tmp {
            msg!("tmp_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let public_inputs = public_inputs_ctx.take()?;
        let mut g_ic = g_ic_ctx.borrow_mut()?;
        let mut tmp = tmp_ctx.borrow_mut()?;

        let public_input = public_inputs[self.input_index as usize];
        let fr_bits = <FrParameters as FpParameters>::MODULUS_BITS as usize;
        let pvk = proof_type.verifying_key();

        const MAX_LOOP: usize = 40;
        BitIteratorBE::new(public_input)
            .skip(256 - fr_bits)
            .skip(self.bit_index as usize)
            .take(MAX_LOOP)
            .for_each(|bit| {
                tmp.double_in_place();
                if bit {
                    tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
                self.bit_index += 1;
            });

        if self.bit_index as usize >= fr_bits {
            g_ic.add_assign(&tmp);
            self.input_index += 1;

            if public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;
                tmp_ctx.fill(G1Projective254::zero())?;
                Ok(FSM::PrepareInputs(self))
            } else {
                if proof_b_ctx.pubkey() != &self.proof_b {
                    msg!("proof_b_ctx pubkey mismatch");
                    return Err(MazeError::UnmatchedAccounts.into());
                }

                let proof_b = proof_b_ctx.take()?;

                let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;
                let r = G2HomProjective254 {
                    x: proof_b.x,
                    y: proof_b.y,
                    z: Fq2::one(),
                };
                let f = Fqk254::one();
                let prepared_input = G1Affine254::from(*g_ic);

                tmp_ctx.erase()?;
                g_ic_ctx.erase()?;
                prepared_input_ctx.fill(prepared_input)?;
                r_ctx.fill(r)?;
                f_ctx.fill(f)?;
                public_inputs_ctx.close()?;
                Ok(FSM::MillerLoop(MillerLoop {
                    index,
                    coeff_index: 0,
                    prepared_input: *prepared_input_ctx.pubkey(),
                    proof_ac: self.proof_ac,
                    proof_b: self.proof_b,
                    r: *r_ctx.pubkey(),
                    f: *f_ctx.pubkey(),
                }))
            }
        } else {
            Ok(FSM::PrepareInputs(self))
        }
    }
}
