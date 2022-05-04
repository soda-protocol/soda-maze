use solana_program::pubkey::Pubkey;

use crate::{vanilla::vanilla::Operation, verifier::{ProofA, ProofB, ProofC}};






pub enum Instruction {
    CreatePool,
    CreateVanillaInfo(Pubkey, Operation),
    CreateProofAccounts(ProofA, ProofB, ProofC),
    
}