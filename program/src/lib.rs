#[allow(missing_docs)]

pub mod error;
pub mod bn;
pub mod verifier;
pub mod entrypoint;
pub mod instruction;
pub mod processor;
pub mod key;

solana_program::declare_id!("BXmQChs6jiUkTdvwWnWkK7A9SZ5eTtWki4yVs8aypEDE");

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{
    entrypoint::ProgramResult,
    program_pack::IsInitialized,
    program_error::ProgramError,
};
use crate::error::MazeError;
use crate::key::*;

pub const HEIGHT: usize = 24;
pub const DEPOSIT_INPUTS: usize = 28;
pub const WITHDRAW_INPUTS: usize = 28;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum OperationType {
    Deposit,
    Withdraw,
}

impl OperationType {
    pub const fn inputs_len(&self) -> usize {
        match self {
            OperationType::Deposit => DEPOSIT_INPUTS,
            OperationType::Withdraw => WITHDRAW_INPUTS,
        }
    }

    pub const fn verifying_key(&self) -> &PreparedVerifyingKey {
        match self {
            OperationType::Deposit => &PreparedVerifyingKey {
                g_ic_init: DEPOSIT_G_IC_INIT,
                gamma_abc_g1: DEPOSIT_GAMMA_ABC_G1,
                alpha_g1_beta_g2: DEPOSIT_ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: DEPOSIT_GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: DEPOSIT_DELTA_G2_NEG_PC,
            },
            // TODO: implement withdraw
            OperationType::Withdraw => &PreparedVerifyingKey {
                g_ic_init: DEPOSIT_G_IC_INIT,
                gamma_abc_g1: DEPOSIT_GAMMA_ABC_G1,
                alpha_g1_beta_g2: DEPOSIT_ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: DEPOSIT_GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: DEPOSIT_DELTA_G2_NEG_PC,
            }
        }
    }
}

pub trait Data: Sized {
    fn to_vec(self) -> Vec<u8>;
}

pub trait Packer: IsInitialized + BorshSerialize + BorshDeserialize {
    const LEN: usize;

    fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        if account.is_initialized() {
            Ok(account)
        } else {
            Err(MazeError::NotInitialized.into())
        }
    }

    fn pack(self, data: &mut [u8]) -> ProgramResult {
        self.serialize(&mut data.as_mut())?;

        Ok(())
    }

    fn initialize(self, data: &mut [u8]) -> ProgramResult {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        if account.is_initialized() {
            Err(MazeError::AlreadyInitialized.into())
        } else {
            self.pack(data)
        }
    }
}
