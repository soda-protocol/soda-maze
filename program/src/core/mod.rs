pub mod vault;
pub mod withdraw;
pub mod node;
pub mod commitment;
pub mod deposit;
pub mod nullifier;

use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::params::{bn::{Fr, G1Projective254}, proof::ProofType, proof::PreparedVerifyingKey};
use crate::verifier::{ProofA, ProofB, ProofC, Verifier, mock::{program::Program, prepare_inputs::PrepareInputs}};
use crate::Packer;

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
        proof_a: ProofA,
        proof_b: ProofB,
        proof_c: ProofC,
    ) -> Verifier {
        let public_inputs = self.to_public_inputs();
        let program = Program::PrepareInputs(PrepareInputs {
            input_index: 0,
            bit_index: 0,
            public_inputs,
            g_ic: *Self::PVK.g_ic_init,
            tmp: G1Projective254::zero(),
            proof_a,
            proof_b,
            proof_c,
        });

        Verifier::new(Self::PROOF_TYPE, credential, program)
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Credential<V: VanillaData> {
    pub is_initialized: bool,
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub vanilla_data: V,
}

pub fn get_credential_pda<'a>(
    vault: &'a Pubkey,
    signer: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], &'a [u8], [u8; 1])) {
    let vault_ref = vault.as_ref();
    let signer_ref = signer.as_ref();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, signer_ref],
        program_id,
    );

    (key, (vault_ref, signer_ref, [seed]))
}

impl<V: VanillaData> Credential<V> {
    pub fn new(vault: Pubkey, owner: Pubkey, vanilla_data: V) -> Self {
        Self {
            is_initialized: true,
            vault,
            owner,
            vanilla_data,
        }
    }
}

impl<V: VanillaData> IsInitialized for Credential<V> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<V: VanillaData> Packer for Credential<V> {
    const LEN: usize = 1 + 32 + 32 + 32 + V::SIZE;
}