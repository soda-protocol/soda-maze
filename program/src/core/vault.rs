use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};
use solana_program::{msg, pubkey::Pubkey, program_pack::IsInitialized, entrypoint::ProgramResult};

use crate::bn::BigInteger256 as BigInteger;
use crate::{params::root::DEFAULT_ROOT_HASH, Packer, error::MazeError};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Vault {
    is_initialized: bool,
    pub enable: bool,
    pub admin: Pubkey,
    pub token_account: Pubkey,
    pub authority: Pubkey,
    pub seed: [u8; 1],
    pub root: BigInteger,
    pub index: u64,
    pub min_deposit: u64,
    pub min_withdraw: u64,
    pub delegate_fee: u64,
}

#[inline]
pub fn get_vault_pda<'a>(
    admin: &'a Pubkey,
    token_mint: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], &'a [u8], [u8; 1])) {
    let admin_ref = admin.as_ref();
    let token_mint_ref = token_mint.as_ref();

    let (key, seed) = Pubkey::find_program_address(
        &[admin_ref, token_mint_ref],
        program_id,
    );

    (key, (admin_ref, token_mint_ref, [seed]))
}

#[inline]
pub fn get_vault_authority_pda<'a>(
    vault: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], [u8; 1])) {
    let vault_ref = vault.as_ref();
    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref],
        program_id,
    );

    (key, (vault_ref, [seed]))
}

impl Vault {
    pub fn new(
        admin: Pubkey,
        token_account: Pubkey,
        authority: Pubkey,
        seed: [u8; 1],
        min_deposit: u64,
        min_withdraw: u64,
        delegate_fee: u64,
    ) -> Self {
        Self {
            is_initialized: true,
            enable: true,
            admin,
            token_account,
            authority,
            seed,
            root: DEFAULT_ROOT_HASH,
            index: 0,
            min_deposit,
            min_withdraw,
            delegate_fee,
        }
    }

    pub fn check_enable(&self) -> ProgramResult {
        if self.enable {
            Ok(())
        } else {
            Err(MazeError::DisbaledVault.into())
        }
    }

    pub fn check_consistency(&self, index: u64, root: &BigInteger) -> ProgramResult {
        if self.index != index {
            msg!("Lastest index of vanilla data does not match with vault");
            return Err(MazeError::InvalidVanillaData.into()); 
        }
        if &self.root != root {
            msg!("Root hash of vanilla data does not match with vault");
            return Err(MazeError::InvalidVanillaData.into()); 
        }
        Ok(())
    }

    pub fn check_deposit(&self, deposit_amount: u64) -> ProgramResult {
        if deposit_amount < self.min_deposit {
            msg!("Deposit amount is less than minimum deposit");
            Err(MazeError::InvalidVanillaData.into())
        } else {
            Ok(())
        }
    }

    pub fn check_withdraw(&self, withdraw_amount: u64) -> ProgramResult {
        if withdraw_amount < self.min_withdraw {
            msg!("Withdraw amount is less than minimum withdraw");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if withdraw_amount < self.delegate_fee {
            msg!("Withdraw amount is less than delegate fee");
            return Err(MazeError::InvalidVanillaData.into());
        }

        Ok(())
    }

    #[inline]
    pub fn signer_seeds<'a>(&'a self, vault: &'a Pubkey) -> [&'a [u8]; 2] {
        [vault.as_ref(), &self.seed]
    }

    pub fn update(&mut self, new_root: BigInteger) {
        self.root = new_root;
        self.index += 1;
    }

    pub fn control(&mut self, enable: bool) {
        self.enable = enable;
    }
}

impl IsInitialized for Vault {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for Vault {
    const LEN: usize = 1 + 1 + 32 + 32 + 32 + 1 + 32 + 8 + 8 + 8 + 8;
}
