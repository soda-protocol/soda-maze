use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{pubkey::Pubkey, instruction::{Instruction, AccountMeta}, system_program, sysvar};
use spl_associated_token_account::get_associated_token_address;

use crate::{
    ID,
    bn::BigInteger256 as BigInteger,
    verifier::{Proof, get_verifier_pda},
    core::{
        nullifier::get_nullifier_pda,
        credential::{get_deposit_credential_pda, get_withdraw_credential_pda},
        commitment::get_commitment_pda,
        vault::{get_vault_pda, get_vault_authority_pda},
        node::{get_merkle_node_pda, gen_merkle_path_from_leaf_index},
        utxo::get_utxo_pda,
    },
    error::MazeError,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum MazeInstruction {
    ResetDepositAccounts,
    CreateDepositCredential {
        deposit_amount: u64,
        leaf: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
    },
    CreateDepositVerifier {
        commitment: Box<Vec<BigInteger>>,
        proof: Box<Proof>,
    },
    VerifyDepositProof,
    FinalizeDeposit {
        utxo: [u8; 32],
    },
    ResetWithdrawAccounts,
    CreateWithdrawCredential {
        withdraw_amount: u64,
        receiver: Pubkey,
        nullifier: BigInteger,
        leaf: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
    },
    CreateWithdrawVerifier {
        proof: Box<Proof>,
    },
    VerifyWithdrawProof,
    FinalizeWithdraw {
        utxo: [u8; 32],
        balance_cipher: u128,
    },
    // 128 ~
    CreateVault {
        min_deposit: u64,
        min_withdraw: u64,
        delegate_fee: u64,
    },
    ControlVault(bool),
}

pub fn create_vault(
    token_mint: Pubkey,
    admin: Pubkey,
    min_deposit: u64,
    min_withdraw: u64,
    delegate_fee: u64,
) -> Result<Instruction, MazeError> {
    let (vault, _) = get_vault_pda(&admin, &token_mint, &ID);
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);

    let data = MazeInstruction::CreateVault {
        min_deposit,
        min_withdraw,
        delegate_fee,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(spl_associated_token_account::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(token_mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_signer, false),
            AccountMeta::new(vault_token_account, false),
            AccountMeta::new_readonly(admin, true),
        ],
        data,
    })
}

pub fn control_vault(vault: Pubkey, admin: Pubkey, enable: bool) -> Result<Instruction, MazeError> {
    let data = MazeInstruction::ControlVault(enable).try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(admin, true),
        ],
        data,
    })
}

pub fn reset_deposit_buffer_accounts(
    vault: Pubkey,
    depositor: Pubkey,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::ResetDepositAccounts.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(depositor, true),
        ],
        data,
    })
}

pub fn create_deposit_credential(
    vault: Pubkey,
    depositor: Pubkey,
    deposit_amount: u64,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);

    let data = MazeInstruction::CreateDepositCredential {
        deposit_amount,
        leaf,
        updating_nodes,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(depositor, true),
        ],
        data,
    })
}

pub fn create_deposit_verifier(
    vault: Pubkey,
    depositor: Pubkey,
    commitment: Box<Vec<BigInteger>>,
    proof: Box<Proof>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    
    let data = MazeInstruction::CreateDepositVerifier {
        commitment,
        proof,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(depositor, true),
        ],
        data,
    })
}

pub fn verify_deposit_proof(
    vault: Pubkey,
    depositor: Pubkey,
    padding: Vec<u8>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let mut data = MazeInstruction::VerifyDepositProof
        .try_to_vec()
        .map_err(|_| MazeError::InstructionUnpackError)?;
    data.extend(padding);

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(credential, false),
            AccountMeta::new(verifier, false),
        ],
        data,
    })
}

pub fn finalize_deposit(
    vault: Pubkey,
    token_mint: Pubkey,
    depositor: Pubkey,
    leaf_index: u64,
    leaf: BigInteger,
    utxo: [u8; 32],
) -> Result<Instruction, MazeError> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (commitment, _) = get_commitment_pda(&leaf, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&depositor, &token_mint);
    let (utxo_key, _) = get_utxo_pda(&utxo, &ID);

    let merkle_path = gen_merkle_path_from_leaf_index(leaf_index);
    let nodes_accounts = merkle_path.into_iter().map(|(layer, index)| {
        let (node, _) = get_merkle_node_pda(
            &vault,
            layer,
            index,
            &ID,
        );
        AccountMeta::new(node, false)
    }).collect::<Vec<_>>();

    let mut accounts = vec![
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(sysvar::rent::ID, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(credential, false),
        AccountMeta::new(verifier, false),
        AccountMeta::new(commitment, false),
        AccountMeta::new(user_token_account, false),
        AccountMeta::new(vault_token_account, false),
        AccountMeta::new(utxo_key, false),
        AccountMeta::new(depositor, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeDeposit {
        utxo,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

pub fn reset_withdraw_buffer_accounts(
    vault: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &receiver, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::ResetWithdrawAccounts.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(delegator, true),
        ],
        data,
    })
}

pub fn create_withdraw_credential(
    vault: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    withdraw_amount: u64,
    nullifier: BigInteger,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &receiver, &ID);

    let data = MazeInstruction::CreateWithdrawCredential {
        withdraw_amount,
        receiver,
        nullifier,
        leaf,
        updating_nodes,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new(credential, false),
            AccountMeta::new(delegator, true),
        ],
        data,
    })
}

pub fn create_withdraw_verifier(
    vault: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    proof: Box<Proof>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &receiver, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::CreateWithdrawVerifier { proof }
        .try_to_vec()
        .map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(delegator, true),
        ],
        data,
    })
}

pub fn verify_withdraw_proof(vault: Pubkey, owner: Pubkey, padding: Vec<u8>) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let mut data = MazeInstruction::VerifyWithdrawProof.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;
    data.extend(padding);

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(credential, false),
            AccountMeta::new(verifier, false),
        ],
        data,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_withdraw(
    vault: Pubkey,
    token_mint: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    leaf_index: u64,
    nullifier: BigInteger,
    utxo: [u8; 32],
    balance_cipher: u128,
) -> Result<Instruction, MazeError> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_withdraw_credential_pda(&vault, &receiver, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&receiver, &token_mint);
    let delegator_token_account = get_associated_token_address(&delegator, &token_mint);
    let (utxo_key, _) = get_utxo_pda(&utxo, &ID);

    let merkle_path = gen_merkle_path_from_leaf_index(leaf_index);
    let nodes_accounts = merkle_path.into_iter().map(|(layer, index)| {
        let (node, _) = get_merkle_node_pda(
            &vault,
            layer,
            index,
            &ID,
        );
        AccountMeta::new(node, false)
    }).collect::<Vec<_>>();

    let mut accounts = vec![
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(spl_associated_token_account::ID, false),
        AccountMeta::new_readonly(sysvar::rent::ID, false),
        AccountMeta::new_readonly(token_mint, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(credential, false),
        AccountMeta::new(verifier, false),
        AccountMeta::new(nullifier, false),
        AccountMeta::new(vault_token_account, false),
        AccountMeta::new(user_token_account, false),
        AccountMeta::new(delegator_token_account, false),
        AccountMeta::new_readonly(vault_signer, false),
        AccountMeta::new(receiver, false),
        AccountMeta::new(utxo_key, false),
        AccountMeta::new(delegator, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeWithdraw {
        utxo,
        balance_cipher,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

#[cfg(test)]
mod tests {
    use solana_program::{pubkey::Pubkey, instruction::Instruction, message::v0::Message, system_program};
    use solana_sdk::{
        transaction::{Transaction, VersionedTransaction}, commitment_config::{CommitmentConfig, CommitmentLevel},
        signature::Keypair, signer::Signer, pubkey, compute_budget::{self, ComputeBudgetInstruction},
        address_lookup_table_account::AddressLookupTableAccount, message::VersionedMessage,
    };
    use solana_address_lookup_table_program::{instruction::{create_lookup_table, extend_lookup_table}, state::AddressLookupTable};
    use solana_transaction_status::UiTransactionEncoding;
    use solana_client::{rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig, rpc_request::RpcRequest};
    use rand_core::{OsRng, RngCore};
    use ark_std::UniformRand;

    use super::{create_vault, create_deposit_credential, create_deposit_verifier, verify_deposit_proof, finalize_deposit};
    use crate::{core::vault::Vault, Packer, verifier::Proof, params::bn::{Fq, Fq2, G1Affine254, G2Affine254}, instruction::{reset_deposit_buffer_accounts, create_withdraw_credential}, core::utxo::UTXO};
    use crate::bn::BigInteger256 as BigInteger;

    const USER_KEYPAIR: &str = "5S4ARoj276VxpUVtcTknVSHg3iLEc4TBY1o5thG8TV2FrMS1mqYMTwg1ec8HQxDqfF4wfkE8oshncqG75LLU2AuT";
    const DEVNET: &str = "https://api.devnet.solana.com";
    const VAULT: Pubkey = pubkey!("EqzRjFAZ9yip1vRG2h9Tmw1o8u9X1DwjQF2nbfCY7YVF");
    const TOKEN_MINT: Pubkey = pubkey!("GR6zSp8opYZh7H2ZFEJBbQYVjY4dkKc19iFoPEhWXTrV");
    const VAULT_SIGNER: Pubkey = pubkey!("9PRMqsWfTTS6SXV2qiSN6E9JypCLtVPRQi8XRphnDbjK");
    const VAULT_TOKEN_ACCOUNT: Pubkey = pubkey!("LMgmSJh5CaCah1bbQ3fENCN2c4kr2xy1gT9EzrhFLKq");
    const DELEGATOR: Pubkey = pubkey!("BpBhecn4QsGVmMVf9YdaeGYeWU7v6S5imj9ViorQbd82");
    const DELEGATOR_TOKEN_ACCOUNT: Pubkey = pubkey!("FKQ6KpRP9rqw8RRiCYs2ouDfMXQjMVJaMzGTUG5nzcW9");
    const LOOKUP_TABLE_ADDRESS: Pubkey = pubkey!("371wbLWY6KamPQ4QgRoZvajLQ72EJyGKu8GemV8scccP");

    #[test]
    fn test_create_lookup_table() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let signer = Keypair::from_base58_string(USER_KEYPAIR);
        let slot = client.get_slot().unwrap();
        let (instruction, pubkey) = create_lookup_table(signer.pubkey(), signer.pubkey(), slot);
        println!("{}", pubkey);

        let blockhash = client.get_latest_blockhash().unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&signer.pubkey()),
            &[&signer],
            blockhash,
        );
        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }

    #[test]
    fn test_append_in_lookup_table() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let signer = Keypair::from_base58_string(USER_KEYPAIR);
        let instruction = extend_lookup_table(
            LOOKUP_TABLE_ADDRESS,
            signer.pubkey(),
            Some(signer.pubkey()),
            vec![
                system_program::ID,
                spl_token::ID,
                spl_associated_token_account::ID,
                solana_program::sysvar::rent::ID,
                TOKEN_MINT,
                VAULT,
                VAULT_SIGNER,
                VAULT_TOKEN_ACCOUNT,
                DELEGATOR,
                DELEGATOR_TOKEN_ACCOUNT,
            ],
        );

        let blockhash = client.get_latest_blockhash().unwrap();
        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&signer.pubkey()),
            &[&signer],
            blockhash,
        );
        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }

    fn send_v0_transaction(client: &RpcClient, signer: &Keypair, instructions: &[Instruction]) -> String {
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(client.commitment().commitment),
            encoding: Some(UiTransactionEncoding::Base64),
            ..RpcSendTransactionConfig::default()
        };

        let lookup_data = client.get_account_data(&LOOKUP_TABLE_ADDRESS).unwrap();
        let lookup_table = AddressLookupTable::deserialize(&lookup_data).unwrap();
        let address_lookup_table_account = AddressLookupTableAccount {
            key: LOOKUP_TABLE_ADDRESS,
            addresses: lookup_table.addresses.to_vec(),
        };

        let blockhash = client.get_latest_blockhash().unwrap();
        let tx = VersionedTransaction::try_new(
            VersionedMessage::V0(Message::try_compile(
                &signer.pubkey(),
                instructions,
                &[address_lookup_table_account],
                blockhash,
            ).unwrap()),
            &[signer],
        ).unwrap();

        client.send(
            RpcRequest::SendTransaction,
            serde_json::json!([
                base64::encode(&bincode::serialize(&tx).unwrap()),
                config,
            ]),
        ).unwrap()
    }

    #[test]
    fn test_instruction() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let signer = Keypair::from_base58_string(USER_KEYPAIR);
        let deposit_amount = 100_000_000;
        let leaf = BigInteger::new([8707106028343764545, 11292527441584175501, 9184329442557567908, 1080097135288411608]);
        let updating_nodes = vec![
            BigInteger::new([11947691383998103714, 4834784687492446865, 17565760189755216598, 1815046295569182153]),
            BigInteger::new([8645684942477193265, 7905943051796661417, 6528092224781116422, 2051256550594740318]),
            BigInteger::new([10249879271600987153, 17511956248817223433, 6616271735050988548, 2109218851817619759]),
            BigInteger::new([8448122782359196270, 8340535543985565928, 9897188560453849320, 2190162733576042750]),
            BigInteger::new([8816700128131285006, 17839287043591934199, 15784021022725366539, 3285764564905563918]),
            BigInteger::new([17744508559234383345, 1255667884698858352, 14697296822926161220, 99018716785599322]),
            BigInteger::new([17167806449891432911, 17973129001636925150, 4740278231544434876, 3064015020807185631]),
            BigInteger::new([2899114760931472613, 11681371941517646843, 15887151360588940911, 1796744982683981404]),
            BigInteger::new([16519950328213487594, 7963203300762907083, 6151628091267361781, 823209739378922314]),
            BigInteger::new([16534649605174599196, 7077838796844029657, 12411398586322807656, 2056791905789759234]),
            BigInteger::new([10714543179285979460, 16802667835348027855, 16048181783836509412, 2163735399925431133]),
            BigInteger::new([11039148008277747653, 14515684053659732226, 4565294480802783748, 1800797764473376749]),
            BigInteger::new([6584597753282041159, 6903601506459256157, 18296889677756858766, 123672224088465622]),
            BigInteger::new([2193608732334948833, 18056198972504476827, 6072813893074928939, 2752142684812128493]),
            BigInteger::new([5500438462734316668, 7967286443546677295, 16936464976013516822, 2560308542255029487]),
            BigInteger::new([13504834167894707005, 952895469753334165, 12515518153860816089, 610351098299808924]),
            BigInteger::new([5208257716809309234, 9087956109532476423, 10202835493222815786, 1249848730058881468]),
            BigInteger::new([12342269562135234524, 3508693137102038809, 17476979880152927951, 1818098262011239368]),
            BigInteger::new([13851103515797334303, 18034375457459603258, 16816139611627825534, 1428371779925500461]),
            BigInteger::new([7536248216859598338, 15082775627295805689, 7476132733304418276, 88853755616718982]),
            BigInteger::new([13249053961652768298, 13291940239181787728, 1860817987128102308, 2877374556902560019]),
        ];
        let commitment = vec![
            BigInteger::new([10437330481268979932, 12637399075367306596, 17925499004937060610, 43109062172724378]),
            BigInteger::new([3723484485398430089, 8836895555723216633, 5072668116932692222, 60243553184384418]),
            BigInteger::new([14071866030200282407, 7408670030862157035, 11133746172882856372, 44081760986066742]),
            BigInteger::new([2082073498537736028, 12619353522392355248, 10591825032917619336, 13565691543249673]),
            BigInteger::new([16363300714787249707, 6675394386760951996, 10566344480761486673, 22560077838168059]),
            BigInteger::new([11548199912325028952, 17349473935940255745, 11795241964892455949, 49506968083183593]),
            BigInteger::new([16636577313445572925, 2713959106249749905, 9027771934823443219, 64044069060076236]),
            BigInteger::new([7736568136752645350, 745746971169088330, 4170573071869497098, 64235486184972024]),
            BigInteger::new([9839856130282344487, 6381701889713366087, 17866217982913531344, 12435661507173254]),
            BigInteger::new([8614237325361520681, 10323540009524416591, 6270779451662671438, 66590805145651076]),
            BigInteger::new([3406731390720981113, 12863445087551629487, 8414776910494561801, 42116836592826880]),
            BigInteger::new([8200788463647772790, 5740871793957135462, 10963954186891381915, 11679620585476262]),
        ];
        let a = G1Affine254::new_const(
            Fq::new(BigInteger::new([4265622909512155139, 11073042774213818299, 14190498758288567971, 612081346563115661])),
            Fq::new(BigInteger::new([848041958524629826, 876964005065317378, 5344773974575634987, 1414580773772336510])),
            false,
        );
        let b = G2Affine254::new_const(
            Fq2::new_const(
                Fq::new(BigInteger::new([1035416798628862582, 12371658611051748338, 15545541503359715510, 1696054959057650493])),
                Fq::new(BigInteger::new([15397477026085967956, 17304156176479981352, 10183130442296187435, 295072668083929975])),
            ),
            Fq2::new_const(
                Fq::new(BigInteger::new([5217088276207174196, 15868092553221817566, 4193341614031321919, 244441080680723902])),
                Fq::new(BigInteger::new([16945577647396140804, 17804110426185850116, 4550216396380936043, 2275431629205922192])),
            ),
            false,
        );
        let c = G1Affine254::new_const(
            Fq::new(BigInteger::new([17927352299501438696, 17120781152786718247, 10035296882566948099, 1181717570369996349])),
            Fq::new(BigInteger::new([15866746016512367982, 11558314611172727440, 7458501409485759096, 2152851189192747376])),
            false,
        );
        let proof = Proof { a, b, c };

        // let instruction = create_vault(token_mint, signer.pubkey(), 10000000, 10000000, 2000000).unwrap();

        let instruction = create_withdraw_credential(
            VAULT,
            signer.pubkey(),
            signer.pubkey(),
            deposit_amount,
            BigInteger::new([17927352299501438696, 17120781152786718247, 10035296882566948099, 1181717570369996349]),
            BigInteger::new([17927352299501438696, 17120781152786718247, 10035296882566948099, 1181717570369996349]),
            Box::new(updating_nodes),
        ).unwrap();

        // let instruction = create_deposit_credential(
        //     VAULT,
        //     signer.pubkey(),
        //     deposit_amount,
        //     leaf,
        //     Box::new(updating_nodes),
        // ).unwrap();

        // let instruction = create_deposit_verifier(
        //     VAULT,
        //     signer.pubkey(),
        //     Box::new(commitment),
        //     Box::new(proof),
        // ).unwrap();

        // let instruction = reset_deposit_buffer_accounts(VAULT, signer.pubkey()).unwrap();

        // for _ in 0..207 {
        //     let blockhash = client.get_latest_blockhash().unwrap();
        //     let data = ComputeBudgetInstruction::RequestUnitsDeprecated { units: 1_400_000, additional_fee: 5000 };
        //     let instruction_1 = Instruction::new_with_borsh(compute_budget::ID, &data, vec![]);
        //     let padding = u64::rand(&mut OsRng).to_le_bytes().to_vec();
        //     let instruction_2 = verify_deposit_proof(VAULT, signer.pubkey(), padding).unwrap();
        //     let transaction = Transaction::new_signed_with_payer(
        //         &[instruction_1, instruction_2],
        //         Some(&signer.pubkey()),
        //         &[&signer],
        //         blockhash,
        //     );
        //     let res = client.send_transaction(&transaction).unwrap();
        //     println!("{:?}", res);
        // }

        // let instruction = finalize_deposit(
        //     VAULT,
        //     token_mint,
        //     signer.pubkey(),
        //     leaf_index,
        //     leaf,
        // ).unwrap();

        let sig = send_v0_transaction(&client, &signer, &[instruction]);
        println!("{}", sig);
    }
}
