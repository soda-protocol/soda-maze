use std::ops::AddAssign;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::context::Context;
use crate::bn::{BnParameters as Bn, BitIteratorBE};
use crate::params::{*, Bn254Parameters as BnParameters};
use crate::{OperationType, error::MazeError, verifier::{ProofA, ProofB, ProofC}};

use super::fsm::FSM;
use super::miller_loop::MillerLoop;

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputs {
    pub input_index: u8,
    pub bit_index: u8,
    pub public_inputs_1: Pubkey, // Vec<Fr>
    pub public_inputs_2: Pubkey, // Vec<Fr>
    pub public_inputs_3: Pubkey, // Vec<Fr>
    pub g_ic: Pubkey, // G1Projective254
    pub tmp: Pubkey, // G1Projective254
}

impl PrepareInputs {
    pub fn process(
        mut self,
        proof_type: &OperationType,
        public_inputs_1_ctx: &Context<Vec<Fr>>,
        public_inputs_2_ctx: &Context<Vec<Fr>>,
        public_inputs_3_ctx: &Context<Vec<Fr>>,
        g_ic_ctx: &Context<G1Projective254>,
        tmp_ctx: &Context<G1Projective254>,
    ) -> Result<FSM, ProgramError> {
        if public_inputs_1_ctx.pubkey() != &self.public_inputs_1 {
            msg!("public_inputs_1 pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if public_inputs_2_ctx.pubkey() != &self.public_inputs_2 {
            msg!("public_inputs_2 pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }
        if public_inputs_3_ctx.pubkey() != &self.public_inputs_3 {
            msg!("public_inputs_3 pubkey mismatch");
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

        let mut public_inputs = public_inputs_1_ctx.take()?;
        public_inputs.extend(public_inputs_2_ctx.take()?);
        public_inputs.extend(public_inputs_3_ctx.take()?);
        
        let mut g_ic = g_ic_ctx.borrow_mut()?;
        let mut tmp = tmp_ctx.borrow_mut()?;

        let public_input = public_inputs[self.input_index as usize];
        let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();
        let bits_len = bits.len();
    
        const MAX_COMPRESS_CYCLE: usize = 64;

        let pvk = proof_type.verifying_key();
        bits
            .into_iter()
            .skip(self.bit_index as usize)
            .take(MAX_COMPRESS_CYCLE)
            .for_each(|bit| {
                tmp.double_in_place();
                if bit {
                    tmp.add_assign_mixed(&pvk.gamma_abc_g1[self.input_index as usize]);
                }
            });
        
        self.bit_index += MAX_COMPRESS_CYCLE as u8;
        if self.bit_index as usize >= bits_len {
            g_ic.add_assign(&tmp);

            self.input_index += 1;
            if public_inputs.get(self.input_index as usize).is_some() {
                self.bit_index = 0;

                tmp_ctx.fill(G1Projective254::zero())?;
                Ok(FSM::PrepareInputs(self))
            } else {
                public_inputs_1_ctx.erase()?;
                public_inputs_2_ctx.erase()?;
                public_inputs_3_ctx.erase()?;
                tmp_ctx.erase()?;
                Ok(FSM::PrepareInputsFinalize(PrepareInputsFinalize {
                    g_ic: self.g_ic,
                }))
            }
        } else {
            Ok(FSM::PrepareInputs(self))
        }
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PrepareInputsFinalize {
    pub g_ic: Pubkey, // G1Projective254
}

impl PrepareInputsFinalize {
    #[allow(clippy::too_many_arguments)]
    pub fn process(
        self,
        proof_a_ctx: &Context<ProofA>,
        proof_b_ctx: &Context<ProofB>,
        proof_c_ctx: &Context<ProofC>,
        g_ic_ctx: &Context<G1Projective254>,
        r_ctx: &Context<G2HomProjective254>,
        f_ctx: &Context<Fqk254>,
        prepared_input_ctx: &Context<G1Affine254>,
    ) -> Result<FSM, ProgramError> {
        if g_ic_ctx.pubkey() != &self.g_ic {
            msg!("g_ic_ctx pubkey mismatch");
            return Err(MazeError::UnmatchedAccounts.into());
        }

        let g_ic = g_ic_ctx.take()?;
        let proof_b = proof_b_ctx.take()?;

        let r = G2HomProjective254 {
            x: proof_b.x,
            y: proof_b.y,
            z: Fq2::one(),
        };
        let f = Fqk254::one();

        let index = (<BnParameters as Bn>::ATE_LOOP_COUNT.len() - 1) as u8;

        r_ctx.fill(r)?;
        f_ctx.fill(f)?;
        prepared_input_ctx.fill(G1Affine254::from(g_ic))?;
        g_ic_ctx.erase()?;
        Ok(FSM::MillerLoop(MillerLoop {
            step: 1,
            index,
            coeff_index: 0,
            prepared_input: *prepared_input_ctx.pubkey(),
            proof_a: *proof_a_ctx.pubkey(),
            proof_b: *proof_b_ctx.pubkey(),
            proof_c: *proof_c_ctx.pubkey(),
            r: *r_ctx.pubkey(),
            f: *f_ctx.pubkey(),
        }))
    }
}