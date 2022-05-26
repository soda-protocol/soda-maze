pub mod vault;
pub mod withdraw;
pub mod node;
pub mod commitment;
pub mod deposit;
pub mod nullifier;
pub mod credential;

use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::entrypoint::ProgramResult;
use solana_program::pubkey::Pubkey;

use crate::params::{bn::{Fr, G1Projective254}, proof::ProofType, proof::PreparedVerifyingKey};
use crate::verifier::{ProofA, ProofB, ProofC, Verifier, mock::{program::Program, prepare_inputs::PrepareInputs}};

pub trait VanillaData:  Clone + BorshSerialize + BorshDeserialize {
    const PROOF_TYPE: ProofType;
    const PVK: &'static PreparedVerifyingKey<'static> = Self::PROOF_TYPE.pvk();
    const INPUTS_LEN: usize = Self::PROOF_TYPE.inputs_len();
    const SIZE: usize;

    fn check_valid(&self) -> ProgramResult;

    fn to_public_inputs(self) -> Box<Vec<Fr>>;

    fn to_verifier(
        self,
        credential: Pubkey,
        proof_a: Box<ProofA>,
        proof_b: Box<ProofB>,
        proof_c: Box<ProofC>,
    ) -> Verifier {
        let public_inputs = self.to_public_inputs();
        let program = Program::PrepareInputs(PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs,
            g_ic: Box::new(*Self::PVK.g_ic_init),
            tmp: Box::new(G1Projective254::zero()),
            proof_a,
            proof_b,
            proof_c,
        });

        Verifier::new(Self::PROOF_TYPE, credential, program)
    }
}
