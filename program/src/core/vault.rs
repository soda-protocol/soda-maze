use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, program_pack::IsInitialized, entrypoint::ProgramResult};

use crate::bn::BigInteger256 as BigInteger;
use crate::{params::root::DEFAULT_ROOT_HASH, Packer, error::MazeError};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub is_initialized: bool,
    pub enable: bool,
    pub admin: Pubkey,
    pub token_account: Pubkey,
    pub authority: Pubkey,
    pub seed: [u8; 1],
    pub root: BigInteger,
    pub index: u64,
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
    pub fn new(admin: Pubkey, token_account: Pubkey, authority: Pubkey, seed: [u8; 1]) -> Self {
        Self {
            is_initialized: true,
            enable: true,
            admin,
            token_account,
            authority,
            seed,
            root: DEFAULT_ROOT_HASH,
            index: 0,
        }
    }

    pub fn check_valid(&self) -> ProgramResult {
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

    #[inline]
    pub fn signer_seeds<'a>(&'a self, vault: &'a Pubkey) -> [&'a [u8]; 2] {
        [vault.as_ref(), &self.seed]
    }

    pub fn update(&mut self, new_root: BigInteger, new_index: u64) {
        self.root = new_root;
        self.index = new_index;
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
    const LEN: usize = 1 + 1 + 32 + 32 + 32 + 1 + 32 + 8;
}
