pub mod program;
pub mod prepare_inputs;
pub mod miller_loop;
pub mod final_exponent;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, hash::Hash, program_pack::IsInitialized, entrypoint::ProgramResult};

use crate::core::VanillaData;
use crate::error::MazeError;
use crate::{Packer, params::verify::ProofType};
use crate::params::bn::{G1Affine254, G2Affine254};
use program::Program;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof {
    pub a: G1Affine254,
    pub b: G2Affine254,
    pub c: G1Affine254,
}

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
    pub credential_hash: Hash,
    pub proof_type: ProofType,
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
    pub fn new(proof_type: ProofType, credential_hash: Hash, program: Program) -> Self {
        Self {
            is_initialized: true,
            proof_type,
            credential_hash,
            program,
        }
    }

    pub fn check_consistency<V: VanillaData>(&self, credential: &V) -> ProgramResult {
        if credential.hash()? != self.credential_hash {
            msg!("credential hash is not matched");
            Err(MazeError::InvalidVanillaData.into())
        } else {
            Ok(())
        }
    }

    pub fn process(self) -> Self {
        let pvk = self.proof_type.pvk();
        let program = self.program.process(pvk);

        Self {
            is_initialized: self.is_initialized,
            proof_type: self.proof_type,
            credential_hash: self.credential_hash,
            program,
        }
    }
}