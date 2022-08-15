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
    },
    error::MazeError,
    store::utxo::{get_utxo_pda, Amount},
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
    FinalizeDeposit,
    ResetWithdrawAccounts,
    CreateWithdrawCredential {
        withdraw_amount: u64,
        nullifier: BigInteger,
        leaf: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
    },
    CreateWithdrawVerifier {
        proof: Box<Proof>,
    },
    VerifyWithdrawProof,
    FinalizeWithdraw,
    // `StoreUtxo` is a temporary method, if `address lookup table` feature of solana is supported,
    // move this into `FinalizeDeposit` and `FinalizeWithdraw`.
    StoreUtxo {
        utxo_key: [u8; 32],
        leaf_index: u64,
        amount: Amount,
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
    owner: Pubkey,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::ResetDepositAccounts.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new(owner, true),
        ],
        data,
    })
}

pub fn create_deposit_credential(
    vault: Pubkey,
    owner: Pubkey,
    deposit_amount: u64,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &owner, &ID);

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
            AccountMeta::new(owner, true),
        ],
        data,
    })
}

pub fn create_deposit_verifier(
    vault: Pubkey,
    owner: Pubkey,
    commitment: Box<Vec<BigInteger>>,
    proof: Box<Proof>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &owner, &ID);
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
            AccountMeta::new(owner, true),
        ],
        data,
    })
}

pub fn verify_deposit_proof(vault: Pubkey, owner: Pubkey, padding: Vec<u8>) -> Result<Instruction, MazeError> {
    let (credential, _) = get_deposit_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let mut data = MazeInstruction::VerifyDepositProof.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;
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
    owner: Pubkey,
    leaf_index: u64,
    leaf: BigInteger,
) -> Result<Instruction, MazeError> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_deposit_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (commitment, _) = get_commitment_pda(&leaf, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&owner, &token_mint);

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
        AccountMeta::new(owner, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeDeposit.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

pub fn reset_withdraw_buffer_accounts(
    vault: Pubkey,
    owner: Pubkey,
    delegator: Pubkey,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);

    let data = MazeInstruction::ResetWithdrawAccounts.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts: vec![
            AccountMeta::new(credential, false),
            AccountMeta::new(verifier, false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new(delegator, true),
        ],
        data,
    })
}

pub fn create_withdraw_credential(
    vault: Pubkey,
    owner: Pubkey,
    delegator: Pubkey,
    withdraw_amount: u64,
    nullifier: BigInteger,
    leaf: BigInteger,
    updating_nodes: Box<Vec<BigInteger>>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &owner, &ID);
    let (nullifier_key, _) = get_nullifier_pda(&nullifier, &ID);

    let data = MazeInstruction::CreateWithdrawCredential {
        withdraw_amount,
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
            AccountMeta::new(nullifier_key, false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new(delegator, true),
        ],
        data,
    })
}

pub fn create_withdraw_verifier(
    vault: Pubkey,
    owner: Pubkey,
    delegator: Pubkey,
    proof: Box<Proof>,
) -> Result<Instruction, MazeError> {
    let (credential, _) = get_withdraw_credential_pda(&vault, &owner, &ID);
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
            AccountMeta::new_readonly(owner, false),
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
    owner: Pubkey,
    delegator: Pubkey,
    leaf_index: u64,
    nullifier: BigInteger,
) -> Result<Instruction, MazeError> {
    let (vault_signer, _) = get_vault_authority_pda(&vault, &ID);
    let (credential, _) = get_withdraw_credential_pda(&vault, &owner, &ID);
    let (verifier, _) = get_verifier_pda(&credential, &ID);
    let (nullifier, _) = get_nullifier_pda(&nullifier, &ID);
    let vault_token_account = get_associated_token_address(&vault_signer, &token_mint);
    let user_token_account = get_associated_token_address(&owner, &token_mint);
    let delegator_token_account = get_associated_token_address(&delegator, &token_mint);

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
        AccountMeta::new(nullifier, false),
        AccountMeta::new(vault_token_account, false),
        AccountMeta::new(user_token_account, false),
        AccountMeta::new(delegator_token_account, false),
        AccountMeta::new_readonly(vault_signer, false),
        // AccountMeta::new(owner, false),
        AccountMeta::new(delegator, true),
    ];
    accounts.extend(nodes_accounts);

    let data = MazeInstruction::FinalizeWithdraw.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

pub fn store_utxo(
    payer: Pubkey,
    utxo_key: [u8; 32],
    leaf_index: u64,
    amount: Amount,
) -> Result<Instruction, MazeError> {
    let (utxo_pubkey, _) = get_utxo_pda(&utxo_key, &ID);

    let accounts = vec![
        AccountMeta::new_readonly(system_program::ID, false),
        AccountMeta::new_readonly(sysvar::rent::ID, false),
        AccountMeta::new(payer, true),
        AccountMeta::new(utxo_pubkey, false),
    ];

    let data = MazeInstruction::StoreUtxo {
        utxo_key,
        leaf_index,
        amount,
    }.try_to_vec().map_err(|_| MazeError::InstructionUnpackError)?;

    Ok(Instruction {
        program_id: ID,
        accounts,
        data,
    })
}

#[cfg(test)]
mod tests {
    use solana_program::{pubkey::Pubkey, instruction::Instruction};
    use solana_sdk::{
        transaction::Transaction, commitment_config::{CommitmentConfig, CommitmentLevel},
        signature::Keypair, signer::Signer, pubkey, compute_budget::{self, ComputeBudgetInstruction},
    };
    use solana_address_lookup_table_program::instruction::create_lookup_table;
    use solana_client::rpc_client::RpcClient;
    use rand_core::{OsRng, RngCore};
    use ark_std::UniformRand;

    use super::{create_vault, create_deposit_credential, create_deposit_verifier, verify_deposit_proof, finalize_deposit};
    use crate::{core::vault::Vault, Packer, verifier::Proof, params::bn::{Fq, Fq2, G1Affine254, G2Affine254}, instruction::reset_deposit_buffer_accounts, store::utxo::UTXO};
    use crate::bn::BigInteger256 as BigInteger;

    const USER_KEYPAIR: &str = "5S4ARoj276VxpUVtcTknVSHg3iLEc4TBY1o5thG8TV2FrMS1mqYMTwg1ec8HQxDqfF4wfkE8oshncqG75LLU2AuT";
    const DEVNET: &str = "https://api.devnet.solana.com";
    const VAULT: Pubkey = pubkey!("BW3Dxk7G5QZHcJZ7GUHaKVqd5J5aPoEXW4wxqUedBS9H");

    #[test]
    fn test_instruction() {
        let client = RpcClient::new_with_commitment(DEVNET, CommitmentConfig {
            commitment: CommitmentLevel::Processed,
        });

        let blockhash = client.get_latest_blockhash().unwrap();
        let signer = Keypair::from_base58_string(USER_KEYPAIR);
        let token_mint = pubkey!("GR6zSp8opYZh7H2ZFEJBbQYVjY4dkKc19iFoPEhWXTrV");

        let deposit_amount = 100;
        let leaf = BigInteger::new([3542236639209175990, 16910505828447755939, 15985469206914547775, 2949265978052157896]);
        let updating_nodes = vec![
            BigInteger::new([15532250321868931685, 772932733899588440, 12868310124187153130, 438462560823777455]),
            BigInteger::new([11847340026267790185, 10820144684227279182, 3897917803026447095, 1211025166583652450]),
            BigInteger::new([13871474726796312921, 2045639111475989628, 12481963867359042585, 1654720166251331239]),
            BigInteger::new([7522360132978259117, 14771120575066486403, 10596590224358807127, 3157651300534472347]),
            BigInteger::new([7507876248263243529, 5715413346482742507, 12957876777088811968, 2510703228340708577]),
            BigInteger::new([133315792692492865, 15293309774567381972, 14334463947285336696, 1723563495644442414]),
            BigInteger::new([1928085400153529539, 1698449431575688062, 5445397574952319768, 1143000330999000263]),
            BigInteger::new([12979161123112243949, 10519306232363901245, 7410924906293113533, 441442420902499555]),
            BigInteger::new([13623320368263364327, 8828774309128316872, 10934886998453446221, 1177057120107296621]),
            BigInteger::new([17522708475201759282, 412032152261673971, 16434968819987934970, 57110405472686226]),
            BigInteger::new([12273231996521786577, 8864960514473101270, 7255808797058973254, 2024561412595145600]),
            BigInteger::new([8041353708081998109, 4408055454208809679, 7467631578407169415, 174481746946129969]),
            BigInteger::new([15759627427490212038, 2342726286939514839, 3188233064319415482, 206053989429984523]),
            BigInteger::new([3862288674501080527, 4414699166683294138, 7867804525257430666, 2497191292622968527]),
            BigInteger::new([18111671256300872493, 9560658010795795413, 11128501249746692797, 3218688909781081982]),
            BigInteger::new([11621730998744754762, 6316575933548212603, 1290755564488270042, 1649482600435840483]),
            BigInteger::new([14372000062670910161, 12363655746768868914, 2239893263450009019, 1148238205359365334]),
            BigInteger::new([7047592107069037456, 15046063210205594002, 8658295702548938809, 1627711097087034838]),
            BigInteger::new([778320942488412995, 1973661381734835396, 12584060032923075028, 1668508506270919639]),
            BigInteger::new([15541703251344978826, 10978453290527186359, 10233791787923230785, 179983619992156155]),
            BigInteger::new([1403833390002913823, 14192997889125093942, 2057500286915250275, 2091709604487301396]),
        ];
        let commitment = vec![
            BigInteger::new([16722997434160713798, 11403452488286244511, 18318868681545149281, 21754274364414989]),
            BigInteger::new([11611806235245355479, 5424040539426569871, 7513338721988059883, 35367902979566062]),
            BigInteger::new([220681830571333505, 13034651635228622148, 14955611269817919911, 36862314553737607]),
            BigInteger::new([3646867184726427713, 5600318523685585750, 7642679702590823310, 40280276519090518]),
            BigInteger::new([2053746354640544201, 5271193340300995188, 15781609477155030499, 33238881268910210]),
            BigInteger::new([4886134654328406654, 12634074070563300144, 17891432476597062324, 71955938858561633]),
            BigInteger::new([2559727239711704880, 6392075204380784424, 12055047205046880238, 9598153984261654]),
            BigInteger::new([8099615302498656019, 17681822004623220591, 4278720356088691622, 20549192218165015]),
            BigInteger::new([1479306651680053975, 16970454663387229825, 1219617339513386804, 9996197586358739]),
            BigInteger::new([12513940028146829811, 16771911556576546385, 12887667978113417874, 36027991776611425]),
            BigInteger::new([18410058132998784786, 13401630289159459721, 14914310748430415085, 18313255534332353]),
            BigInteger::new([5826441929749290616, 11335202586746830014, 10903293645248433631, 36117579937827459]),
        ];
        let a = G1Affine254::new_const(
            Fq::new(BigInteger::new([3750417186220724512, 3978078781434640716, 15163791108043952614, 2453596515077279990])),
            Fq::new(BigInteger::new([5354853820532153524, 8883007908664368954, 470161243035897903, 1359038641147964963])),
            false
        );
        let b = G2Affine254::new_const(
            Fq2::new_const(
                Fq::new(BigInteger::new([12118601996045181130, 896706683785346415, 4709517509465227924, 1819241630933245065])),
                Fq::new(BigInteger::new([16349181015735361827, 4843110160248729036, 17714835083434401718, 2754712195795085383])),
            ),
            Fq2::new_const(
                Fq::new(BigInteger::new([3167422245359854874, 15117403505212976980, 14561078193533486427, 992932037830603307])),
                Fq::new(BigInteger::new([10453996433908490996, 4951364747808814581, 1077088453432665796, 3244165116791247838])),
            ),
            false
        );
        let c = G1Affine254::new_const(
            Fq::new(BigInteger::new([6745960168647187300, 7304089792560402287, 5467772039812183716, 1531927553351135845])),
            Fq::new(BigInteger::new([2914263778726088111, 9472631376659388131, 16215105594981982902, 939471742250680668])),
            false
        );
        let proof = Proof { a, b, c };

        let instruction = create_vault(token_mint, signer.pubkey(), 10, 10, 2).unwrap();

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

        

        let transaction = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&signer.pubkey()),
            &[&signer],
            blockhash,
        );
        let res = client.send_transaction(&transaction).unwrap();
        println!("{}", res);
    }
}
