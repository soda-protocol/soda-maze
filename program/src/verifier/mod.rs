pub mod fsm;
pub mod mock;
pub mod prepare_inputs;
pub mod miller_loop;
pub mod final_exponent;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::{Packer, params::ProofType};
use crate::params::bn::{G1Affine254, G2Affine254};
use mock::fsm::FSM;

pub type ProofA = G1Affine254;

pub type ProofB = G2Affine254;

pub type ProofC = G1Affine254;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct ProofAC {
    pub proof_a: ProofA,
    pub proof_c: ProofC,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Verifier {
    pub is_initialized: bool,
    pub proof_type: ProofType,
    pub credential: Pubkey,
    pub fsm: FSM,
}

impl IsInitialized for Verifier {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Verifier {
    const LEN: usize = 2048;
}

impl Verifier {
    pub fn new(proof_type: ProofType, credential: Pubkey, fsm: FSM) -> Self {
        Self {
            is_initialized: true,
            proof_type,
            credential,
            fsm,
        }
    }
}