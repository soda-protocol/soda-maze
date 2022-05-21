use solana_program::{pubkey::Pubkey, account_info::{AccountInfo, next_account_infos, next_account_info}, entrypoint::ProgramResult, rent::Rent, sysvar::Sysvar};

use crate::{params::bn::Fr, HEIGHT};



#[inline(never)]
pub fn process_deposit_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    commitment: Fr,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let rent = Rent::from_account_info(next_account_info(accounts_iter)?)?;
    let pool_info = next_account_info(accounts_iter)?;
    let deposit_info = next_account_info(accounts_iter)?;
    let friends_infos = accounts_iter.take(HEIGHT);

    


    Ok(())
}