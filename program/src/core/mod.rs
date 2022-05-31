pub mod vault;
pub mod withdraw;
pub mod node;
pub mod commitment;
pub mod deposit;
pub mod nullifier;
pub mod credential;

use std::fmt::Debug;
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::entrypoint::ProgramResult;
use solana_program::pubkey::Pubkey;

use crate::bn::{BigInteger256 as BigInteger, FpParameters};
use crate::params::bn::FrParameters;
use crate::params::{verify::ProofType, verify::PreparedVerifyingKey};
use crate::verifier::{Proof, Verifier, program::Program, prepare_inputs::PrepareInputs};

#[inline(always)]
pub fn is_fr_valid(fr: &BigInteger) -> bool {
    fr < &<FrParameters as FpParameters>::MODULUS
}

pub trait VanillaData: Debug + Clone + BorshSerialize + BorshDeserialize {
    const PROOF_TYPE: ProofType;
    const PVK: &'static PreparedVerifyingKey<'static> = Self::PROOF_TYPE.pvk();
    const INPUTS_LEN: usize = Self::PROOF_TYPE.inputs_len();
    const SIZE: usize;

    fn check_valid(&self) -> ProgramResult;

    fn to_public_inputs(self) -> Box<Vec<BigInteger>>;

    fn to_verifier(
        self,
        credential: Pubkey,
        proof: Box<Proof>,
    ) -> Verifier {
        let public_inputs = self.to_public_inputs();
        let program = Program::PrepareInputs(PrepareInputs::new(
            Self::PVK,
            public_inputs,
            proof,
        ));

        Verifier::new(Self::PROOF_TYPE, credential, program)
    }
}
