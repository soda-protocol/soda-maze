pub mod program;
pub mod prepare_inputs;
pub mod miller_loop;
pub mod final_exponent;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::{Packer, params::proof::ProofType};
use crate::params::bn::{G1Affine254, G2Affine254};
use self::program::Program;

pub type ProofA = G1Affine254;

pub type ProofB = G2Affine254;

pub type ProofC = G1Affine254;

pub fn get_verifier_pda<'a>(
    credential: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1])) {
    let credential_ref = credential.as_ref();

    let (key, seed) = Pubkey::find_program_address(
        &[credential_ref],
        program_id,
    );

    (key, (credential_ref, [seed]))
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Verifier {
    pub is_initialized: bool,
    pub proof_type: ProofType,
    pub credential: Pubkey,
    pub program: Program,
}

impl IsInitialized for Verifier {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Verifier {
    const LEN: usize = 3072;
}

impl Verifier {
    pub fn new(proof_type: ProofType, credential: Pubkey, program: Program) -> Self {
        Self {
            is_initialized: true,
            proof_type,
            credential,
            program,
        }
    }

    pub fn process(self) -> Self {
        let pvk = self.proof_type.pvk();
        let program = self.program.process(pvk);

        Self {
            is_initialized: self.is_initialized,
            proof_type: self.proof_type,
            credential: self.credential,
            program,
        }
    }
}