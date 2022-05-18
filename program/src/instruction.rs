use solana_program::pubkey::Pubkey;

use crate::{verifier::{ProofA, ProofB, ProofC}};






pub enum Instruction {
    CreatePool,
    CreateVanillaInfo(Pubkey),
    CreateProofAccounts(ProofA, ProofB, ProofC),
}