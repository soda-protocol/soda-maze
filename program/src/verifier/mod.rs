pub mod fsm;
pub mod mock;
pub mod prepare_inputs;
pub mod miller_loop;
pub mod final_exponent;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::params::bn::{G1Affine254, G2Affine254};

pub type ProofA = G1Affine254;
pub type ProofB = G2Affine254;
pub type ProofC = G1Affine254;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct ProofAC {
    pub proof_a: ProofA,
    pub proof_c: ProofC,
}
