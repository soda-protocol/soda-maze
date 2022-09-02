use std::str::FromStr;
use ark_ec::{AffineCurve, ProjectiveCurve};
use clap::Parser;
use num_traits::Zero;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, signature::Signature, pubkey::Pubkey};
use solana_transaction_status::{UiTransactionEncoding, EncodedTransaction, UiMessage, UiInstruction, UiParsedInstruction};
use soda_maze_program::{core::{commitment::Commitment, nullifier::{get_nullifier_pda, Nullifier}}, Packer, ID};
use soda_maze_utils::{parser::{from_hex_string, to_hex_string}, convert::{from_maze_edwards_affine, to_maze_edwards_affine}};

#[cfg(feature = "bn254")]
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr};
#[cfg(feature = "bls12-381")]
use ark_ed_on_bls12_381::{EdwardsAffine, Fr};

#[inline]
fn decrypt(commitment_0: EdwardsAffine, privkey: Fr) -> EdwardsAffine {
    // pk * C0
    commitment_0.mul(privkey).into_affine()
}

fn reveal_commitment<I: Iterator<Item = EdwardsAffine>>(commitment_1: EdwardsAffine, states: I) -> EdwardsAffine {
    // ∑state_i = ∑pk_i * C0 = r * P
    let sum = states
        .into_iter()
        .fold(EdwardsProjective::zero(), |sum, state| {
            sum.add_mixed(&state)
        });
    // C1 - r * P = nullifier * G + r * P - r * P = nullifier * G
    (commitment_1.into_projective() - sum).into_affine()
}

#[derive(Parser, Debug)]
#[clap(name = "Soda Maze Eye", version = "0.0.1", about = "Reveal illegal receiver address of deposit/withdraw finalize transaction")]
enum Opt {
    GetCommitment {
        #[clap(short = 'u', long, value_parser, default_value = "https://api.devnet.solana.com")]
        url: String,
        #[clap(short = 's', long, value_parser)]
        signature: String,
    },
    Decrypt {
        #[clap(short = 'p', long = "private-key")]
        privkey: String,
        #[clap(short = 'c', long = "commitment-0", value_parser)]
        commitment_0: String,
    },
    Reveal {
        #[clap(short = 'u', long, value_parser, default_value = "https://api.devnet.solana.com")]
        url: String,
        #[clap(short = 's', long, value_parser)]
        state: Vec<String>,
        #[clap(short = 'c', long = "commitment-1", value_parser)]
        commitment_1: String,
    }
}

fn main() {
    let opt = Opt::parse();

    match opt {
        Opt::GetCommitment {
            url,
            signature,
        } => {
            let sig = Signature::from_str(&signature).expect("invalid signature");
            let client = RpcClient::new_with_commitment(
                &url,
                CommitmentConfig::finalized(),
            );

            let tx = client.get_transaction(&sig, UiTransactionEncoding::JsonParsed)
                .expect("get transaction error");
            let commitment_key = match tx.transaction.transaction {
                EncodedTransaction::Json(tx_data) => {
                    match tx_data.message {
                        UiMessage::Parsed(ref message) => {
                            assert_eq!(message.instructions.len(), 1);
                            let instruction = &message.instructions[0];
                            match instruction {
                                UiInstruction::Parsed(instruction) => {
                                    match instruction {
                                        UiParsedInstruction::PartiallyDecoded(instruction) => {
                                            let data = bs58::decode(&instruction.data).into_vec().unwrap();
                                            match data[0] {
                                                // deposit
                                                3 => Pubkey::from_str(&instruction.accounts[6]).unwrap(),
                                                // withdraw
                                                7 => Pubkey::from_str(&instruction.accounts[9]).unwrap(),
                                                _ => unreachable!("instruction should be deposit or withdraw"),
                                            }
                                        }
                                        _ => unreachable!("parsed instruction should be partially decoded"),
                                    }
                                }
                                _ => unreachable!("instruction type should by parsed"),
                            }
                        }
                        _ => unreachable!("message type should by parsed"),
                    }
                }
                _ => unreachable!("transaction type should be json"),
            };

            let commitment_data = client.get_account_data(&commitment_key).expect("get commitment data failed");
            let commitment = Commitment::unpack(&commitment_data).expect("unpack commitment error");
            let commitment_0 = from_maze_edwards_affine(commitment.inner.0).expect("invalid commitment inner 0");
            let commitment_1 = from_maze_edwards_affine(commitment.inner.1).expect("invalid commitment inner 1");

            println!("commitment 0: {}", to_hex_string(&commitment_0).unwrap());
            println!("commitment 1: {}", to_hex_string(&commitment_1).unwrap());
        }
        Opt::Decrypt {
            privkey,
            commitment_0,
        } => {
            let privkey = from_hex_string::<Fr>(privkey).expect("invalid private key");
            let commitment_0 = from_hex_string(commitment_0).expect("invalid commitment 0");
            let state = decrypt(commitment_0, privkey);

            println!("output state is {}", to_hex_string(&state).unwrap());
        }
        Opt::Reveal {
            url,
            state,
            commitment_1,
        } => {
            let states = state.into_iter().enumerate().map(|(i, s)| {
                from_hex_string(s).expect(format!("invalid state at {}", i).as_str())
            });
            let commitment_1 = from_hex_string(commitment_1).expect("invalid commitment 1");
            let client = RpcClient::new_with_commitment(
                &url,
                CommitmentConfig::finalized(),
            );

            let nullifier_point = reveal_commitment(commitment_1, states);
            let nullifier_point = to_maze_edwards_affine(nullifier_point);
            let (nullifier, _) = get_nullifier_pda(&nullifier_point, &ID);
            if let Ok(data) = client.get_account_data(&nullifier) {
                if let Ok(nullifier) = Nullifier::unpack(&data) {
                    println!("Asset has been withdrawn! receiver is {}", nullifier.receiver);
                } else {
                    println!("Asset has not been withdrawn yet.");
                }
            } else {
                println!("Asset has not been withdrawn yet.");
            }
        }
    }
}
