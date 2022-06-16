#[allow(missing_docs)]

pub mod error;
pub mod bn;
pub mod verifier;
pub mod entrypoint;
pub mod instruction;
pub mod processor;
pub mod core;
pub mod params;
pub mod invoke;

solana_program::declare_id!("CxdQFBMBvymks2TQxkpR98rzETngs6kkaqvcxX36hTi9");

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::pubkey::Pubkey;
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_pack::IsInitialized,
    program_error::ProgramError,
};

use crate::error::MazeError;

pub trait Packer: IsInitialized + BorshSerialize + BorshDeserialize {
    const LEN: usize;

    #[doc(hidden)]
    fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        if account.is_initialized() {
            Ok(account)
        } else {
            Err(MazeError::NotInitialized.into())
        }
    }

    #[doc(hidden)]
    fn pack(&self, data: &mut [u8]) -> ProgramResult {
        self.serialize(&mut data.as_mut())?;
        Ok(())
    }

    #[doc(hidden)]
    fn initialize(&self, data: &mut [u8]) -> ProgramResult {
        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        if account.is_initialized() {
            Err(MazeError::AlreadyInitialized.into())
        } else {
            self.pack(data)
        }
    }

    fn initialize_to_account_info(
        &self,
        account_info: &AccountInfo,
    ) -> ProgramResult {
        self.initialize(&mut account_info.try_borrow_mut_data()?)
    }

    fn unpack_from_account_info(
        account_info: &AccountInfo,
        program_id: &Pubkey,
    ) -> Result<Self, ProgramError> {
        if account_info.owner != program_id {
            return Err(MazeError::InvalidAccountOwner.into());
        }
        if account_info.data_len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        Self::unpack(&account_info.try_borrow_data()?)
    }

    fn pack_to_account_info(
        &self,
        account_info: &AccountInfo,
    ) -> ProgramResult {
        self.pack(&mut account_info.try_borrow_mut_data()?)
    }
}
