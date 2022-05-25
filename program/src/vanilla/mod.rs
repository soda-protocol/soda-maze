pub mod pool;
pub mod withdraw;
pub mod node;
pub mod commitment;
pub mod deposit;
pub mod nullifier;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::params::{HEIGHT, bn::{Fr, G1Projective254}};
use crate::context::{Context512, Context1536};
use crate::state::VerifyState;
use crate::Packer;

#[inline]
pub fn is_updating_nodes_valid(nodes: &[Fr]) -> bool {
    if nodes.len() != HEIGHT {
        false
    } else {
        nodes.iter().all(|x| x.is_valid())
    }
}

pub trait VanillaData: Clone + BorshSerialize + BorshDeserialize {
    fn check_valid(&self) -> ProgramResult;

    fn to_public_inputs(self) -> Box<Vec<Fr>>;

    fn to_verify_state(
        self,
        g_ic_ctx: &Context512<G1Projective254>,
        tmp_ctx: &Context512<G1Projective254>,
        public_inputs_ctx: &Context1536<Box<Vec<Fr>>>,
        proof_ac_pukey: Pubkey,
        proof_b_pukey: Pubkey,
    ) -> Result<VerifyState, ProgramError>;
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Credential<V: VanillaData, const VLEN: usize> {
    pub is_initialized: bool,
    pub pool: Pubkey,
    pub owner: Pubkey,
    pub vanilla_data: V,
}

impl<V: VanillaData, const VLEN: usize> IsInitialized for Credential<V, VLEN> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<V: VanillaData, const VLEN: usize> Packer for Credential<V, VLEN> {
    const LEN: usize = 1 + 32 + 32 + 32 + VLEN;
}