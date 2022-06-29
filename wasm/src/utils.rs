use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger256};
use easy_aes::{full_decrypt, full_encrypt, BLOCK, Keys};
use solana_program::pubkey::Pubkey;
use solana_program::hash::hash;

pub fn encrypt_balance(sig: &[u8], vault: &Pubkey, balance: u64) -> [u8; 16] {
    let key = hash(&[sig, vault.as_ref()].concat()).to_bytes();
    let key1 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&key.as_ref()[..16]).unwrap()));
    let key2 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&key.as_ref()[16..]).unwrap()));

    let mut block = BLOCK::new(u128::from(balance).to_le_bytes());
    full_encrypt(&mut block, &key1);
    full_encrypt(&mut block, &key2);
    block.stringify_block()
}

pub fn decrypt_balance(sig: &[u8], vault: &Pubkey, cipher: [u8; 16]) -> u64 {
    let key = hash(&[sig, vault.as_ref()].concat()).to_bytes();
    let key1 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&key.as_ref()[..16]).unwrap()));
    let key2 = Keys::from(BLOCK::new(<[u8; 16]>::try_from(&key.as_ref()[16..]).unwrap()));

    let mut block = BLOCK::new(cipher);
    full_decrypt(&mut block, &key2);
    full_decrypt(&mut block, &key1);
    u128::from_le_bytes(block.stringify_block()) as u64
}

pub fn gen_secret(sig: &[u8], vault: &Pubkey) -> Fr {
    let mut secret = hash(&[sig, vault.as_ref()].concat()).to_bytes();
    // strip 3 last bits to make sure secret is in Fr
    secret[31] &= 0b0001_1111;
    let secret = [
        u64::from_le_bytes([secret[0], secret[1], secret[2], secret[3], secret[4], secret[5], secret[6], secret[7]]),
        u64::from_le_bytes([secret[8], secret[9], secret[10], secret[11], secret[12], secret[13], secret[14], secret[15]]),
        u64::from_le_bytes([secret[16], secret[17], secret[18], secret[19], secret[20], secret[21], secret[22], secret[23]]),
        u64::from_le_bytes([secret[24], secret[25], secret[26], secret[27], secret[28], secret[29], secret[30], secret[31]]),
    ];
    Fr::from_repr(BigInteger256::new(secret)).unwrap()
}

pub fn gen_utxo_key(sig: &[u8], vault: &Pubkey, nonce: u64) -> [u8; 32] {
    let key = hash(&[sig, vault.as_ref(), &nonce.to_le_bytes()].concat());
    key.to_bytes()
}

#[cfg(test)]
mod tests {
    use solana_sdk::pubkey;

    use super::{encrypt_balance, decrypt_balance};

    #[test]
    fn test_encrypt_balance() {
        let sig = [240,216,117,240,182,7,202,232,195,55,124,100,227,85,238,54,136,253,116,157,255,221,124,116,236,250,132,87,92,97,70,76,34,183,248,5,17,141,147,24,156,139,198,166,60,44,6,158,166,148,47,87,98,12,254,132,62,115,71,210,58,157,61,3];
        let vault = pubkey!("BW3Dxk7G5QZHcJZ7GUHaKVqd5J5aPoEXW4wxqUedBS9H");
        let balance = 7000000;

        let cipher = encrypt_balance(&sig, &vault, balance);
        println!("{:x?}", &cipher);
        let amount = decrypt_balance(&sig, &vault, cipher);
        println!("{:?}", amount);
    }
}