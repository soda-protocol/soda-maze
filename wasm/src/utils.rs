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