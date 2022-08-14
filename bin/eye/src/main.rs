use std::str::FromStr;
use std::path::PathBuf;
use ark_ff::{FpParameters, BigInteger256, PrimeField};
use ark_bn254::Fr;
use num_integer::Integer;
use num_bigint::BigUint;
use num_bigint_dig::{Sign, BigInt as BigIntDig};
use clap::Parser;
use soda_maze_lib::vanilla::encryption::biguint_array_to_biguint;
use soda_maze_program::{core::{commitment::Commitment, nullifier::{get_nullifier_pda, Nullifier}}, Packer, ID};
use soda_maze_types::params::{JsonParser, RabinPrimes, RabinParameters};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, signature::Signature, pubkey::Pubkey};
use solana_transaction_status::{UiTransactionEncoding, EncodedTransaction, UiMessage};

fn rabin_decrypt(cipher: &BigIntDig, modulus: &BigIntDig, p: &BigIntDig, q: &BigIntDig) -> (BigIntDig, BigIntDig, BigIntDig, BigIntDig) {
    assert_eq!(*modulus, p * q);
    let (exp_p, rem) = (p + &BigIntDig::from(1u64)).div_rem(&BigIntDig::from(4u64));
    assert_eq!(rem, BigIntDig::from(0u64));
    let (exp_q, rem) = (q + &BigIntDig::from(1u64)).div_rem(&BigIntDig::from(4u64));
    assert_eq!(rem, BigIntDig::from(0u64));

    let mp = cipher.modpow(&exp_p, p);
    let mq = cipher.modpow(&exp_q, q);

    let egcd = p.extended_gcd(&q);
    assert_eq!(egcd.gcd, BigIntDig::from(1u64));

    let r = (&egcd.x * p * &mq + &egcd.y * q * &mp) % modulus;
    let r_neg = modulus - &r;
    let s = (&egcd.x * p * &mq - &egcd.y * q * &mp) % modulus;
    let s_neg = modulus - &s;

    (r, r_neg, s, s_neg)
}

fn substract_nullifier_pda(preimage: &BigIntDig, len: usize, bit_size: usize) -> Pubkey {
    use soda_maze_program::bn::BigInteger256;

    let (sign, preimage) = preimage.to_bytes_le();
    assert_ne!(sign, Sign::Minus);
    let preimage = BigUint::from_bytes_le(&preimage);

    let mut nullifier_len = <Fr as PrimeField>::Params::MODULUS_BITS as usize / bit_size;
    if <Fr as PrimeField>::Params::MODULUS_BITS as usize % bit_size != 0 {
        nullifier_len += 1;
    }
    let base = BigUint::from(1u64) << ((len - nullifier_len) * bit_size);
    let nullifier = Fr::from(preimage / &base);

    let nullifier = BigInteger256::new(nullifier.into_repr().0);
    let (nullifier_key, _) = get_nullifier_pda(&nullifier, &ID);

    nullifier_key
}

#[derive(Parser, Debug)]
#[clap(name = "Soda Maze Eye", version = "0.0.1", about = "Reveal illegal deposit informations", long_about = "")]
enum Opt {
    RabinReveal {
        #[clap(short = 'u', long, value_parser, default_value = "https://api.devnet.solana.com")]
        url: String,
        #[clap(long = "rabin-param", parse(from_os_str))]
        rabin_params: PathBuf,
        #[clap(long = "rabin-prime", parse(from_os_str))]
        rabin_primes: PathBuf,
        #[clap(short, long, value_parser)]
        signature: String,
    }
}

fn main() {
    let opt = Opt::parse();

    match opt {
        Opt::RabinReveal {
            url,
            rabin_params,
            rabin_primes,
            signature,
        } => {
            let rabin_params = RabinParameters::from_file(&rabin_params).expect("read rabin parameters from file error");
            let rabin_primes = RabinPrimes::from_file(&rabin_primes).expect("read rabin primes from file error");
            let p = hex::decode(rabin_primes.prime_a).expect("invalid rabin primes");
            let q = hex::decode(rabin_primes.prime_b).expect("invalid rabin primes");
            let modulus = hex::decode(rabin_params.modulus).expect("invalid rabin params");

            let client = &RpcClient::new_with_commitment(
                &url,
                CommitmentConfig::finalized(),
            );
            let sig = Signature::from_str(&signature).expect("invalid signature");
            let tx = client.get_transaction(&sig, UiTransactionEncoding::Json)
                .expect("get transaction error");
            let commitment_key = match tx.transaction.transaction {
                EncodedTransaction::Json(tx_data) => {
                    match tx_data.message {
                        UiMessage::Raw(ref message) => {
                            assert_eq!(message.account_keys.len(), 32);
                            let commitment_key = &message.account_keys[5];
                            Pubkey::from_str(commitment_key).unwrap()
                        }
                        _ => unreachable!("message type should by raw"),
                    }
                }
                _ => unreachable!("transaction type should be json"),
            };
        
            let commitment_data = client.get_account_data(&commitment_key).expect("get commitment data failed");
            let commitment = Commitment::unpack(&commitment_data).expect("unpack commitment error");
            let cipher_array = commitment.cipher.iter().map(|c| {
                Fr::from_repr(BigInteger256::new(c.0)).unwrap().into()
            }).collect::<Vec<BigUint>>();
            let cipher = biguint_array_to_biguint(&cipher_array, rabin_params.bit_size * rabin_params.cipher_batch);
        
            let cipher = BigIntDig::from_bytes_le(Sign::Plus, &cipher.to_bytes_le());
            let p = BigIntDig::from_bytes_le(Sign::Plus, &p);
            let q =  BigIntDig::from_bytes_le(Sign::Plus, &q);
            let modulus = BigIntDig::from_bytes_le(Sign::Plus, &modulus);
            let (v1, v2, v3, v4) = rabin_decrypt(&cipher, &modulus, &p, &q);

            // 4 solves
            let key = substract_nullifier_pda(&v1, rabin_params.modulus_len, rabin_params.bit_size);
            let nullifier_data = client.get_account_data(&key).expect("get nullifier data error");
            if !nullifier_data.is_empty() {
                let nullifier = Nullifier::unpack(&nullifier_data).expect("unpack nullifier error");
                println!("withdraw owner pubkey: {}", nullifier.owner);
                return;
            }

            let key = substract_nullifier_pda(&v2, rabin_params.modulus_len, rabin_params.bit_size);
            let nullifier_data = client.get_account_data(&key).expect("get nullifier data error");
            if !nullifier_data.is_empty() {
                let nullifier = Nullifier::unpack(&nullifier_data).expect("unpack nullifier error");
                println!("withdraw owner pubkey: {}", nullifier.owner);
                return;
            }

            let key = substract_nullifier_pda(&v3, rabin_params.modulus_len, rabin_params.bit_size);
            let nullifier_data = client.get_account_data(&key).expect("get nullifier data error");
            if !nullifier_data.is_empty() {
                let nullifier = Nullifier::unpack(&nullifier_data).expect("unpack nullifier error");
                println!("withdraw owner pubkey: {}", nullifier.owner);
                return;
            }

            let key = substract_nullifier_pda(&v4, rabin_params.modulus_len, rabin_params.bit_size);
            let nullifier_data = client.get_account_data(&key).expect("get nullifier data error");
            if !nullifier_data.is_empty() {
                let nullifier = Nullifier::unpack(&nullifier_data).expect("unpack nullifier error");
                println!("withdraw owner pubkey: {}", nullifier.owner);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rabin_decryption() {
        // use num_bigint::BigUint;
        use num_integer::Integer;
        use num_bigint_dig::{RandPrime, BigUint, BigInt};
        use rand_core::OsRng;
        use crate::rabin_decrypt;

        let mut rng = OsRng;

        let bit_len = 1488;
        let (p, q): (BigInt, BigInt);
        let div = BigUint::from(4u64);
        let rem = BigUint::from(3u64);
        loop {
            let v = rng.gen_prime(bit_len);
            let (_, r) = v.div_rem(&div);
            if r == rem {
                p = v.into();
                break;
            }
        };
        loop {
            let v = rng.gen_prime(bit_len);
            let (_, r) = v.div_rem(&div);
            if r == rem {
                q = v.into();
                break;
            }
        };

        let modulus = &p * &q;
        let preimage = BigInt::from(1u64) << (bit_len - 2);
        let (_, cipher) = (&preimage * &preimage).div_rem(&modulus);

        let (v1, v2, v3, v4) = rabin_decrypt(&cipher, &modulus, &p, &q);
        println!("{}", v1.eq(&preimage));
        println!("{}", v2.eq(&preimage));
        println!("{}", v3.eq(&preimage));
        println!("{}", v4.eq(&preimage));
    }

}
