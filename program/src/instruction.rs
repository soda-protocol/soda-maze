use solana_program::pubkey::Pubkey;

use crate::{verifier::{ProofA, ProofB, ProofC}};






pub enum Instruction {
    CreatePool,
    CreateVanillaData(Pubkey),
    CreateProofAccounts(ProofA, ProofB, ProofC),
}