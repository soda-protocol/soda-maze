use arrayref::array_refs;
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::{
    msg,
    pubkey::Pubkey,
    entrypoint::ProgramResult,
    program_pack::IsInitialized,
    program_error::ProgramError,
};

use crate::params::bn::{Fr, G1Projective254};
use crate::params::vk::get_prepared_verifying_key;
use crate::{HEIGHT, PUBLIC_INPUTS};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger, Packer};
use crate::verifier::{prepare_inputs::PrepareInputs, fsm::FSM};
use crate::context::{Context512, Context1536};
use crate::state::VerifyState;

use super::credential::is_credential_valid;

#[inline]
fn pubkey_to_fr(pubkey: Pubkey) -> Fr {
    let pubkey = &pubkey.to_bytes();
    let (d0, d1, d2, d3) = array_refs![pubkey, 8, 8, 8, 8];    
    let repr = [
        u64::from_le_bytes(*d0),
        u64::from_le_bytes(*d1),
        u64::from_le_bytes(*d2),
        u64::from_le_bytes(*d3) & ((1u64 << 61) - 1),
    ];

    Fr::from_repr(BigInteger::new(repr)).unwrap()
}

#[inline]
fn is_updating_nodes_valid(nodes: &[Fr]) -> bool {
    if nodes.len() != HEIGHT {
        false
    } else {
        nodes.iter().all(|x| x.is_valid())
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawInfo {
    pub mint: Pubkey,
    pub withdraw_amount: u64,
    pub nullifier: Fr,
    pub credential: Vec<Fr>,
    pub root: Fr,
    pub new_leaf: Fr,
    pub new_leaf_index: u64,
    pub updating_nodes: Vec<Fr>,
}

impl WithdrawInfo {
    pub fn check_valid(&self) -> ProgramResult {
        if !self.root.is_valid() {
            msg!("root is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.new_leaf.is_valid() {
            msg!("new leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_credential_valid(&self.credential) {
            msg!("credential is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_updating_nodes_valid(&self.updating_nodes) {
            msg!("updating nodes are invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if self.new_leaf_index >= 1 << HEIGHT {
            msg!("leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }

        Ok(())
    }

    pub fn to_public_inputs(self) -> Box<Vec<Fr>> {
        let mut inputs = Box::new(Vec::with_capacity(PUBLIC_INPUTS));

        inputs.push(pubkey_to_fr(self.mint));
        inputs.push(Fr::from_repr(BigInteger::from(self.withdraw_amount)).unwrap());
        inputs.push(self.nullifier);
        inputs.extend(self.credential);
        inputs.push(self.root);
        inputs.push(Fr::from_repr(BigInteger::from(self.new_leaf_index)).unwrap());
        inputs.push(self.new_leaf);
        inputs.extend(self.updating_nodes);

        assert_eq!(inputs.len(), PUBLIC_INPUTS);

        inputs
    }

    pub fn to_verify_state(
        self,
        g_ic_ctx: &Context512<G1Projective254>,
        tmp_ctx: &Context512<G1Projective254>,
        public_inputs_ctx: &Context1536<Box<Vec<Fr>>>,
        proof_ac_pukey: Pubkey,
        proof_b_pukey: Pubkey,
    ) -> Result<VerifyState, ProgramError> {
        let pvk = get_prepared_verifying_key();
        let public_inputs = self.to_public_inputs();

        g_ic_ctx.fill(*pvk.g_ic_init)?;
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

        Ok(VerifyState::new(fsm))
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VanillaInfo {
    pub is_initialized: bool,
    pub withdraw_info: WithdrawInfo,
    pub operator: Pubkey,
    pub verify_state: Pubkey,
}

impl VanillaInfo {
    pub fn new(withdraw_info: WithdrawInfo, operator: Pubkey, verify_state: Pubkey) -> Self {
        Self {
            is_initialized: true,
            withdraw_info,
            operator,
            verify_state,
        }
    }
}

impl IsInitialized for VanillaInfo {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for VanillaInfo {
    const LEN: usize = 1024;
}
