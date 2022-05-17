#[allow(missing_docs)]

pub mod error;
pub mod bn;
pub mod verifier;
pub mod entrypoint;
pub mod instruction;
pub mod processor;
pub mod vk;
pub mod vanilla;
pub mod params;
pub mod context;
pub mod state;

solana_program::declare_id!("BXmQChs6jiUkTdvwWnWkK7A9SZ5eTtWki4yVs8aypEDE");

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_memory::sol_memset;
use solana_program::pubkey::Pubkey;
use solana_program::{
    msg,
    rent::Rent,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program_pack::IsInitialized,
    program_error::ProgramError,
};

use crate::error::MazeError;
use crate::vk::PreparedVerifyingKey;

pub const HEIGHT: usize = 26;
pub const DEPOSIT_INPUTS: usize = 31;
pub const WITHDRAW_INPUTS: usize = 44;
pub const CREDENTIAL_LEN: usize = 12;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum ProofType {
    Deposit,
    Withdraw,
}

impl ProofType {
    pub const fn inputs_len(&self) -> usize {
        match self {
            ProofType::Deposit => DEPOSIT_INPUTS,
            ProofType::Withdraw => WITHDRAW_INPUTS,
        }
    }

    pub const fn pvk(&self) -> &PreparedVerifyingKey {
        match self {
            ProofType::Deposit => &PreparedVerifyingKey {
                g_ic_init: vk::deposit::G_IC_INIT,
                gamma_abc_g1: vk::deposit::GAMMA_ABC_G1,
                alpha_g1_beta_g2: vk::deposit::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: vk::deposit::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: vk::deposit::DELTA_G2_NEG_PC,
            },
            // TODO: implement withdraw
            ProofType::Withdraw => &PreparedVerifyingKey {
                g_ic_init: vk::withdraw::G_IC_INIT,
                gamma_abc_g1: vk::withdraw::GAMMA_ABC_G1,
                alpha_g1_beta_g2: vk::withdraw::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: vk::withdraw::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: vk::withdraw::DELTA_G2_NEG_PC,
            }
        }
    }
}

pub trait Data: Sized {
    fn to_vec(self) -> Vec<u8>;
}

pub trait Packer: IsInitialized + BorshSerialize + BorshDeserialize {
    const LEN: usize;

    fn unpack_from_account_info(
        account_info: &AccountInfo,
        program_id: &Pubkey,
    ) -> Result<Self, ProgramError> {
        if account_info.owner != program_id {
            return Err(MazeError::InvalidAccountOwner.into());
        }
        Self::unpack(&account_info.try_borrow_data()?)
    }

    fn unchecked_unpack_from_account_info(
        account_info: &AccountInfo,
        program_id: &Pubkey,
    ) -> Result<Option<Self>, ProgramError> {
        if account_info.owner != program_id {
            return Err(MazeError::InvalidAccountOwner.into());
        }
        Self::unchecked_unpack(&account_info.try_borrow_data()?)
    }

    fn erase_account_info(account_info: &AccountInfo) -> ProgramResult {
        sol_memset(&mut account_info.try_borrow_mut_data()?, 0, Self::LEN);
        
        Ok(())
    }

    fn initialize_to_account_info(
        &self,
        rent: &Rent,
        account_info: &AccountInfo,
        program_id: &Pubkey,
    ) -> ProgramResult {
        if account_info.owner != program_id {
            return Err(MazeError::InvalidAccountOwner.into());
        }
        assert_rent_exempt(rent, account_info)?;
        self.initialize(&mut account_info.try_borrow_mut_data()?)
    }

    fn unchecked_initialize_to_account_info(
        &self,
        rent: &Rent,
        account_info: &AccountInfo,
    ) -> ProgramResult {
        assert_rent_exempt(rent, account_info)?;
        self.pack(&mut account_info.try_borrow_mut_data()?)
    }

    fn pack_to_account_info(
        &self,
        account_info: &AccountInfo,
    ) -> ProgramResult {
        self.pack(&mut account_info.try_borrow_mut_data()?)
    }

    #[doc(hidden)]
    fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        if account.is_initialized() {
            Ok(account)
        } else {
            Err(MazeError::NotInitialized.into())
        }
    }

    #[doc(hidden)]
    fn unchecked_unpack(data: &[u8]) -> Result<Option<Self>, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }

        let account: Self = BorshDeserialize::deserialize(&mut data.as_ref())?;
        Ok(account.is_initialized().then(|| account))
    }

    #[doc(hidden)]
    fn pack(&self, data: &mut [u8]) -> ProgramResult {
        self.serialize(&mut data.as_mut())?;

        Ok(())
    }

    #[doc(hidden)]
    fn initialize(&self, data: &mut [u8]) -> ProgramResult {
        if data.len() != Self::LEN {
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

#[inline]
fn assert_rent_exempt(rent: &Rent, account_info: &AccountInfo) -> ProgramResult {
    if !rent.is_exempt(account_info.lamports(), account_info.data_len()) {
        msg!("minimum rent: {}", &rent.minimum_balance(account_info.data_len()));
        Err(MazeError::NotRentExempt.into())
    } else {
        Ok(())
    }
}
