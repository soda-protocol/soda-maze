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
        commitment::{get_commitment_pda, InnerCommitment},
        vault::{get_vault_pda, get_vault_authority_pda},
        node::{get_merkle_node_pda, gen_merkle_path_from_leaf_index},
        utxo::get_utxo_pda, GroupAffine,
    },
    error::MazeError,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum MazeInstruction {
    CreateDepositCredential {
        deposit_amount: u64,
        leaf: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
        commitment: InnerCommitment,
    },
    CreateDepositVerifier {
        proof: Box<Proof>,
    },
    VerifyDepositProof,
    FinalizeDeposit {
        utxo: [u8; 32],
    },
    CreateWithdrawCredential {
        withdraw_amount: u64,
        receiver: Pubkey,
        nullifier: GroupAffine,
        leaf: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
        commitment: InnerCommitment,
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

    println!("vault {}", &vault);
    println!("vailt signer {}", &vault_signer);
    println!("vault token account {}", &vault_token_account);

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

pub fn create_deposit_credential(
    vault: Pubkey,
    depositor: Pubkey,
    deposit_amount: u64,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
    commitment: InnerCommitment,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);

    let data = MazeInstruction::CreateDepositCredential {
        deposit_amount,
        leaf,
        updating_nodes,
        commitment,
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
    proof: Box<Proof>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &depositor, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    
    let data = MazeInstruction::CreateDepositVerifier {
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

pub fn create_withdraw_credential(
    vault: Pubkey,
    receiver: Pubkey,
    delegator: Pubkey,
    withdraw_amount: u64,
    nullifier: GroupAffine,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
    commitment: InnerCommitment,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &delegator, &receiver, &ID);

    let data = MazeInstruction::CreateWithdrawCredential {
        withdraw_amount,
        receiver,
        nullifier,
        leaf,
        updating_nodes,
        commitment,
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
    let (credential, _) = get_withdraw_credential_pda(&vault, &delegator, &receiver, &ID);
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

pub fn verify_withdraw_proof(vault: Pubkey, delegator: &Pubkey, owner: Pubkey, padding: Vec<u8>) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, delegator, &owner, &ID);
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
    leaf: BigInteger,
    nullifier: GroupAffine,
    utxo: [u8; 32],
    balance_cipher: u128,
) -> Result<Instruction, MazeError> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_withdraw_credential_pda(&vault, &delegator, &receiver, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);
    let (commitment, _) = get_commitment_pda(&leaf, &ID);
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
        AccountMeta::new(commitment, false),
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

    use super::{create_vault, create_deposit_credential, create_deposit_verifier, verify_deposit_proof, finalize_deposit, finalize_withdraw};
    use crate::{core::{commitment::InnerCommitment, GroupAffine}, Packer, verifier::Proof, params::bn::{Fq, Fq2, G1Affine254, G2Affine254}, instruction::create_withdraw_credential, core::utxo::UTXO};
    use crate::bn::BigInteger256 as BigInteger;

    const USER_KEYPAIR: &str = "5S4ARoj276VxpUVtcTknVSHg3iLEc4TBY1o5thG8TV2FrMS1mqYMTwg1ec8HQxDqfF4wfkE8oshncqG75LLU2AuT";
    const DEVNET: &str = "https://api.devnet.solana.com";
    const VAULT: Pubkey = pubkey!("GhDjmnDESa9M6Pvo6ihLMcJpS7nUDV7RDGtudD7JtGvC");
    const TOKEN_MINT: Pubkey = pubkey!("GR6zSp8opYZh7H2ZFEJBbQYVjY4dkKc19iFoPEhWXTrV");
    const VAULT_SIGNER: Pubkey = pubkey!("EtF8UoLMXZo2aDbdhpCF6CimqX2Jbx8FLf7r47MfyUQS");
    const VAULT_TOKEN_ACCOUNT: Pubkey = pubkey!("FYGQw8kGMZsdktKMno9XLwKwpfBYxHmP5oC3C33xtC5e");
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
        let leaf = BigInteger::new([10238628474373320456, 14022387074461718602, 2475330134695199970, 1313074002618417116]);
        let updating_nodes = vec![
            BigInteger::new([13964979764574450530, 6814902463828884090, 3490476130675498614, 939454355663535017]),
            BigInteger::new([12524172229863401954, 4796040823255991742, 4069760990520073033, 868000759613921587]),
            BigInteger::new([1596125167915367140, 6156920030815160090, 10382505956980516360, 2927580863364086847]),
            BigInteger::new([1765955334735741199, 1291223536655544861, 16639810887409821899, 880497050557539739]),
            BigInteger::new([12643707220000567509, 11436727266683695517, 4732916465160176110, 1964838653473584553]),
            BigInteger::new([15885659284373961508, 5471913312835855211, 2653419779047489694, 1900210723210987730]),
            BigInteger::new([10596518041243485014, 11924227743320673010, 287941000929346776, 245476564885753827]),
            BigInteger::new([9798514336536856130, 3632004711427197341, 11339261941566790797, 3119499272359887178]),
            BigInteger::new([10570135904687397455, 18190639330091595662, 17985847417806757659, 2492070591683873349]),
            BigInteger::new([13472515854679819921, 6007832876773512197, 945556273399982984, 126431182602079263]),
            BigInteger::new([8536281558937608028, 12462637082463092570, 4313476410340840383, 2403661115683713579]),
            BigInteger::new([7973243436672073066, 16221803217086044779, 1982661521783632814, 1972000485319446447]),
        ];
        let commitment = (
            GroupAffine {
                x: BigInteger::new([4426581770956920, 3780038317459993260, 5978800350633987884, 311273432824146036]),
                y: BigInteger::new([8863000400804113423, 1348204775686030698, 8545119952742531791, 2800637279200743611]),
            },
            GroupAffine {
                x: BigInteger::new([7215792706979548681, 9873107139232219479, 865173140646005947, 1248029139033987868]),
                y: BigInteger::new([17291355517249880028, 3312550530945056926, 17870307985785161756, 610666079189054042]),
            },
        );
        let a = G1Affine254::new_const(
            Fq::new(BigInteger::new([17381767644818340984, 3751637970425688463, 11897723137901410286, 2628054590150868757])),
            Fq::new(BigInteger::new([12495087938492610491, 7315845434515123162, 14658457518751987503, 447599317579503610])),
            false,
        );
        let b = G2Affine254::new_const(
            Fq2::new_const(
                Fq::new(BigInteger::new([11289918167215668305, 5596130612184073396, 6192789515876855109, 3279723092958874358])),
                Fq::new(BigInteger::new([17879507732148848603, 10369508746801824971, 17344640418009863013, 1539253996629113496])),
            ),
            Fq2::new_const(
                Fq::new(BigInteger::new([6007973111967089812, 9258705278091649435, 7183941806421198646, 578300671118975326])),
                Fq::new(BigInteger::new([12128663196347054577, 16180755230900641998, 6739960301757964946, 502830956916105034])),
            ),
            false,
        );
        let c = G1Affine254::new_const(
            Fq::new(BigInteger::new([15171433465355968616, 7015032887021418538, 13285711323354563888, 1074691968068496779])),
            Fq::new(BigInteger::new([13242131963254593196, 12366386926853818962, 14772137643134677909, 2758687257485180845])),
            false,
        );
        let proof = Proof { a, b, c };

        // let instruction = create_vault(TOKEN_MINT, signer.pubkey(), 10000000, 10000000, 2000000).unwrap();

        // let instruction = create_deposit_credential(
        //     VAULT,
        //     signer.pubkey(),
        //     deposit_amount,
        //     leaf,
        //     Box::new(updating_nodes),
        //     commitment,
        // ).unwrap();

        // let instruction = create_deposit_verifier(
        //     VAULT,
        //     signer.pubkey(),
        //     Box::new(proof),
        // ).unwrap();

        // let instruction = reset_deposit_buffer_accounts(VAULT, signer.pubkey()).unwrap();

        // for _ in 0..145 {
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

        let instruction = finalize_withdraw(
            VAULT,
            TOKEN_MINT,
            DELEGATOR,
            signer.pubkey(),
            0,
            leaf,
            commitment.0,
            [1u8; 32],
            100_000_000,
        ).unwrap();

        let blockhash = client.get_latest_blockhash().unwrap();
        let sig = client.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
            &[instruction],
            Some(&signer.pubkey()),
            &[&signer],
            blockhash,
        )).unwrap();

        // let sig = send_v0_transaction(&client, &signer, &[instruction]);
        // println!("{}", sig);
    }
}
