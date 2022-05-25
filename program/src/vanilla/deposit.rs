use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::{
    msg,
    pubkey::Pubkey,
    entrypoint::ProgramResult,
    program_error::ProgramError,
};

use crate::params::{bn::{Fr, G1Projective254}, rabin::RABIN_MODULUS_LEN, ProofType, HEIGHT, vk::PreparedVerifyingKey};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger, state::VerifyState};
use crate::verifier::{prepare_inputs::PrepareInputs, fsm::FSM};
use crate::context::{Context512, Context1536};

use super::{is_updating_nodes_valid, commitment::is_commitment_valid, VanillaData, Credential};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositVanillaData {
    pub deposit_amount: u64,
    pub leaf_index: u64,
    pub leaf: Fr,
    pub prev_root: Fr,
    pub updating_nodes: Box<Vec<Fr>>,
    pub commitment: Box<Vec<Fr>>,
}

impl VanillaData for DepositVanillaData {
    fn check_valid(&self) -> ProgramResult {
        if self.leaf_index >= 1 << HEIGHT {
            msg!("leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.leaf.is_valid() {
            msg!("leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.prev_root.is_valid() {
            msg!("prev root is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_updating_nodes_valid(&self.updating_nodes) {
            msg!("updating nodes are invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_commitment_valid(&self.commitment) {
            msg!("commitment is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }

        Ok(())
    }

    fn to_public_inputs(self) -> Box<Vec<Fr>> {
        const PROOF_TYPE: ProofType = ProofType::Deposit;
        const INPUTS_LEN: usize = PROOF_TYPE.inputs_len();

        let mut inputs = Box::new(Vec::with_capacity(INPUTS_LEN));

        inputs.push(Fr::from_repr(BigInteger::from(self.deposit_amount)).unwrap());
        inputs.push(Fr::from_repr(BigInteger::from(self.leaf_index)).unwrap());
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.extend(*self.updating_nodes);
        inputs.extend(*self.commitment);

        assert_eq!(inputs.len(), INPUTS_LEN);

        inputs
    }

    fn to_verify_state(
        self,
        g_ic_ctx: &Context512<G1Projective254>,
        tmp_ctx: &Context512<G1Projective254>,
        public_inputs_ctx: &Context1536<Box<Vec<Fr>>>,
        proof_ac_pukey: Pubkey,
        proof_b_pukey: Pubkey,
    ) -> Result<VerifyState, ProgramError> {
        const PROOF_TYPE: ProofType = ProofType::Deposit;
        const PVK: &PreparedVerifyingKey = PROOF_TYPE.pvk();

        let public_inputs = self.to_public_inputs();

        g_ic_ctx.fill(*PVK.g_ic_init)?;
        tmp_ctx.fill(G1Projective254::zero())?;
        public_inputs_ctx.fill(public_inputs)?;

        let fsm = FSM::PrepareInputs(PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs: *public_inputs_ctx.pubkey(),
            g_ic: *g_ic_ctx.pubkey(),
            tmp: *tmp_ctx.pubkey(),
            proof_ac: proof_ac_pukey,
            proof_b: proof_b_pukey,
        });

        Ok(VerifyState::new(PROOF_TYPE, fsm))
    }
}

const DEPOSIT_VANILLA_LEN: usize = 8 + 8 + 32 + 32 + (HEIGHT + 1) * 32 + RABIN_MODULUS_LEN * 32;

pub type DepositCredential = Credential<DepositVanillaData, DEPOSIT_VANILLA_LEN>;
