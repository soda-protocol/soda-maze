//! Error types
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use solana_program::{
    msg,
    decode_error::DecodeError,
    program_error::{ProgramError, PrintProgramError},
};
use thiserror::Error;

/// Errors that may be returned by the TokenLending program.
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum MazeError {
    #[error("Account is already initialized")]
    AlreadyInitialized,
    #[error("Vault is disabled")]
    DisbaledVault,
    #[error("Accounts are not matched")]
    UnmatchedAccounts,
    #[error("Vanilla proof data is invalid")]
    InvalidVanillaData,
    #[error("Proof is not verified")]
    ProofNotVerified,
    #[error("Pda pubkey is invalid")]
    InvalidPdaPubkey,
    #[error("Input account owner is not the program address")]
    InvalidAccountOwner,
    #[error("Authority is an invalid signer")]
    InvalidAuthority,
    #[error("Invalid context status")]
    InvalidContextStatus,
    #[error("Failed to unpack instruction data")]
    InstructionUnpackError,
    #[error("Lamport balance below rent-exempt threshold")]
    NotRentExempt,
    #[error("Account is not initialized")]
    NotInitialized,
}

impl From<MazeError> for ProgramError {
    fn from(e: MazeError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl<T> DecodeError<T> for MazeError {
    fn type_of() -> &'static str {
        "Soda Maze Error"
    }
}

impl PrintProgramError for MazeError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        msg!(self.to_string().as_str());
    }
}
