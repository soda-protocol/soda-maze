use solana_program::{pubkey::Pubkey, account_info::AccountInfo, entrypoint::ProgramResult};

use crate::verifier::process_test;

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _input: &[u8],
) -> ProgramResult {
    process_test();

    Ok(())
}

#[cfg(test)]
mod tests {
    use solana_program::instruction::Instruction;
    use solana_sdk::{transaction::Transaction, commitment_config::{CommitmentConfig, CommitmentLevel}, signature::Keypair, signer::Signer};
    use solana_client::rpc_client::{RpcClient};

    use crate::{id, processor::process_instruction};

    const USER_KEYPAIR: &str = "25VtdefYWzk4fvyfAg3RzSrhwmy4HhgPyYcxetmHRmPrkCsDqSJw8Jav7tWCXToV6e1L7nGxhyEDnWYVsDHUgiZ7";
    const DEVNET: &str = "https://api.devnet.solana.com";

    #[test]
    fn test_instruction() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let blockhash = client.get_latest_blockhash().unwrap();
        let user = Keypair::from_base58_string(USER_KEYPAIR);

        let transaction = Transaction::new_signed_with_payer(
            &[Instruction {
                program_id: id(),
                accounts: vec![],
                data: vec![],
            }],
            Some(&user.pubkey()),
            &[&user],
            blockhash,
        );

        client.send_transaction(&transaction).unwrap();
    }
}