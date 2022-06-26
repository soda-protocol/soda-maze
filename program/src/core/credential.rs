use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;

use crate::Packer;
use super::VanillaData;

const DEPOSIT_TAG: &[u8] = &[0];
const WITHDRAW_TAG: &[u8] = &[1];

pub fn get_deposit_credential_pda<'a>(
    vault: &'a Pubkey,
    owner: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], &'a [u8], &'static [u8], [u8; 1])) {
    let vault_ref = vault.as_ref();
    let owner_ref = owner.as_ref();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &DEPOSIT_TAG, owner_ref],
        program_id,
    );

    (key, (vault_ref, owner_ref, DEPOSIT_TAG, [seed]))
}

pub fn get_withdraw_credential_pda<'a>(
    vault: &'a Pubkey,
    owner: &'a Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, (&'a [u8], &'a [u8], &'static [u8], [u8; 1])) {
    let vault_ref = vault.as_ref();
    let owner_ref = owner.as_ref();

    let (key, seed) = Pubkey::find_program_address(
        &[vault_ref, &WITHDRAW_TAG, owner_ref],
        program_id,
    );

    (key, (vault_ref, owner_ref, WITHDRAW_TAG, [seed]))
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Credential<V: VanillaData> {
    pub is_initialized: bool,
    pub vault: Pubkey,
    pub owner: Pubkey,
    pub vanilla_data: V,
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
    const LEN: usize = 1 + 32 + 32 + V::SIZE;
}
