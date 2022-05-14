use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::context::Context;
use crate::bn::{BnParameters as Bn, BitIteratorBE};
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::{OperationType, error::MazeError, verifier::ProofB};

use super::fsm::FSM;
use super::miller_loop::MillerLoop;

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u16,
    pub public_inputs: Pubkey, // Vec<Fr>
    pub g_ic: Pubkey, // G1Projective254
    pub tmp: Pubkey, // G1Projective254
    pub proof_a: Pubkey,
    pub proof_b: Pubkey,
    pub proof_c: Pubkey,
}

impl PrepareInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        mut self,
        proof_type: &OperationType,
        public_inputs_ctx: &Context<Box<Vec<Fr>>>,
        g_ic_ctx: &Context<G1Projective254>,
        tmp_ctx: &Context<G1Projective254>,
        proof_b_ctx: &Context<ProofB>,
        prepared_input_ctx: &Context<G1Affine254>,
        r_ctx: &Context<G2HomProjective254>,
        f_ctx: &Context<Fqk254>,
    ) -> Result<FSM, ProgramError> {
        if public_inputs_ctx.pubkey() != &self.public_inputs {
            msg!("public_inputs pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
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
        let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();
        let bits_len = bits.len();
        let pvk = proof_type.verifying_key();

        const MAX_LOOP: usize = 52;
        bits
            .into_iter()
            .skip(self.bit_index as usize)
            .take(MAX_LOOP)
            .for_each(|bit| {
                tmp.double_in_place();
                if bit {
                    tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
            });

        self.bit_index += MAX_LOOP as u16;
        if self.bit_index as usize >= bits_len {
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
                public_inputs_ctx.erase()?;
                prepared_input_ctx.fill(prepared_input)?;
                r_ctx.fill(r)?;
                f_ctx.fill(f)?;
                g_ic_ctx.erase()?;

                Ok(FSM::MillerLoop(MillerLoop {
                    index,
                    coeff_index: 0,
                    prepared_input: *prepared_input_ctx.pubkey(),
                    proof_a: self.proof_a,
                    proof_b: self.proof_b,
                    proof_c: self.proof_c,
                    r: *r_ctx.pubkey(),
                    f: *f_ctx.pubkey(),
                }))
            }
        } else {
            Ok(FSM::PrepareInputs(self))
        }
    }
}
