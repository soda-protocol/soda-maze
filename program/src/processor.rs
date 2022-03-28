use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult, log::sol_log_compute_units};

use crate::verifier::process_test;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    sol_log_compute_units();
    process_test();
    sol_log_compute_units();

    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_program_test::*;
    use solana_sdk::{transaction::Transaction, signer::Signer};

    use crate::{id, processor::process_instruction};

    #[tokio::test]
    async fn test_instruction() {
        let mut test = ProgramTest::new(
            "test",
            id(),
            processor!(process_instruction),
        );
        test.set_compute_max_units(200_000);

        let (mut banks_client, payer, recent_blockhash) = test.start().await;

        let transaction = Transaction::new_signed_with_payer(
            &[],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );

        banks_client.process_transaction(transaction).await.unwrap();
    }
}