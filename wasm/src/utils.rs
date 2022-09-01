use aes::{Aes256Enc, Aes256Dec};
use aes::cipher::{generic_array::GenericArray, KeyInit, BlockEncrypt, BlockDecrypt};
use ark_bn254::Bn254;
use ark_ec::{twisted_edwards_extended::{GroupProjective, GroupAffine}, ProjectiveCurve};
use ark_ed_on_bn254::{Fq as Fr, Fr as Frr, EdwardsParameters};
use ark_ff::{PrimeField, BigInteger, BigInteger256, FpParameters};
use ark_groth16::Proof;
use num_traits::ToPrimitive;
use solana_program::{pubkey::Pubkey, hash::hash};
use soda_maze_program::core::{GroupAffine as MazeGroupAffine, commitment::InnerCommitment};
use soda_maze_program::{verifier::Proof as MazeProof, bn::BigInteger256 as MazeBigInteger};
use solana_sdk::signature::Signature;

pub fn get_nullifier_pubkey(leaf_index: u64, secret: Fr) -> Pubkey {
    use soda_maze_lib::params::poseidon::get_poseidon_bn254_for_nullifier;
    use soda_maze_lib::vanilla::hasher::{FieldHasher, poseidon::PoseidonHasher};
    use soda_maze_program::{core::nullifier::get_nullifier_pda, ID};

    let ref params = get_poseidon_bn254_for_nullifier();
    let nullifier = PoseidonHasher::hash(params, &[Fr::from(leaf_index), secret]).unwrap();
    let nullifier: <Fr as PrimeField>::BigInt = nullifier.into();
    let mut nullifier_bits = nullifier.to_bits_le();
    nullifier_bits.truncate(<<Frr as PrimeField>::Params as FpParameters>::CAPACITY as usize);
    let nullifier: <Frr as PrimeField>::BigInt = <<Frr as PrimeField>::BigInt as BigInteger>::from_bits_le(&nullifier_bits);
    // nullifier_point = nullifier * G
    let nullifier_point: GroupAffine<EdwardsParameters> = GroupProjective::prime_subgroup_generator().mul(nullifier).into();

    let nullifier_point = to_maze_group_affine(nullifier_point);
    let (nullifier, _) = get_nullifier_pda(&nullifier_point, &ID);
    nullifier
}

pub fn encrypt_balance(sig: &Signature, vault: &Pubkey, balance: u64) -> u128 {
    let key = hash(&[sig.as_ref(), vault.as_ref()].concat()).to_bytes();
    let key = GenericArray::from(key);
    let encryptor = Aes256Enc::new(&key);
    let mut block = GenericArray::from((balance as u128).to_le_bytes());
    encryptor.encrypt_block(&mut block);
    u128::from_le_bytes(<[u8; 16]>::try_from(block.as_ref()).unwrap())
}

pub fn decrypt_balance(sig: &Signature, vault: &Pubkey, cipher: u128) -> u64 {
    let key = hash(&[sig.as_ref(), vault.as_ref()].concat()).to_bytes();
    let key = GenericArray::from(key);
    let decryptor = Aes256Dec::new(&key);
    let mut block = GenericArray::from(cipher.to_le_bytes());
    decryptor.decrypt_block(&mut block);
    u128::from_le_bytes(<[u8; 16]>::try_from(block.as_ref()).unwrap())
        .to_u64()
        .expect("Error: invalid balance cipher")
}

pub fn gen_secret(sig: &Signature, vault: &Pubkey) -> Fr {
    let mut secret = hash(&[sig.as_ref(), vault.as_ref()].concat()).to_bytes();
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

#[inline]
pub fn gen_utxo_key(sig: &Signature, vault: &Pubkey, nonce: u64) -> [u8; 32] {
    let key = hash(&[sig.as_ref(), vault.as_ref(), &nonce.to_le_bytes()].concat());
    key.to_bytes()
}

#[inline]
pub fn from_maze_fr_repr(fr: MazeBigInteger) -> Fr {
    Fr::from_repr(BigInteger256::new(fr.0)).expect("Error: invalid fr repr")
}

#[inline]
pub fn to_maze_fr_repr(fr: Fr) -> MazeBigInteger {
    MazeBigInteger::new(fr.into_repr().0)
}

#[inline]
pub fn to_maze_group_affine(g: GroupAffine<EdwardsParameters>) -> MazeGroupAffine {
    MazeGroupAffine {
        x: to_maze_fr_repr(g.x),
        y: to_maze_fr_repr(g.y),
    }
}

#[inline]
pub fn to_maze_commitment(c: (GroupAffine<EdwardsParameters>, GroupAffine<EdwardsParameters>)) -> InnerCommitment {
    (to_maze_group_affine(c.0), to_maze_group_affine(c.1))
}

#[inline]
pub fn to_maze_proof(p: Proof<Bn254>) -> MazeProof {
    use soda_maze_program::params::bn::{Fq, Fq2, G1Affine254, G2Affine254};

    MazeProof {
        a: G1Affine254::new(
            Fq::new(MazeBigInteger::new(p.a.x.0.0)),
            Fq::new(MazeBigInteger::new(p.a.y.0.0)),
            p.a.infinity,
        ),
        b: G2Affine254::new(
            Fq2::new(
                Fq::new(MazeBigInteger::new(p.b.x.c0.0.0)),
                Fq::new(MazeBigInteger::new(p.b.x.c1.0.0)),
            ),
            Fq2::new(
                Fq::new(MazeBigInteger::new(p.b.y.c0.0.0)),
                Fq::new(MazeBigInteger::new(p.b.y.c1.0.0)),
            ),
            p.b.infinity,
        ),
        c: G1Affine254::new(
            Fq::new(MazeBigInteger::new(p.c.x.0.0)),
            Fq::new(MazeBigInteger::new(p.c.y.0.0)),
            p.c.infinity,
        ),
    }
}

// #[cfg(test)]
// mod tests {
//     use solana_sdk::pubkey;

//     use super::{encrypt_balance, decrypt_balance};

//     #[test]
//     fn test_encrypt_balance() {
//         let sig = [240,216,117,240,182,7,202,232,195,55,124,100,227,85,238,54,136,253,116,157,255,221,124,116,236,250,132,87,92,97,70,76,34,183,248,5,17,141,147,24,156,139,198,166,60,44,6,158,166,148,47,87,98,12,254,132,62,115,71,210,58,157,61,3];
//         let vault = pubkey!("BW3Dxk7G5QZHcJZ7GUHaKVqd5J5aPoEXW4wxqUedBS9H");
//         let balance = 7000000;

//         let cipher = encrypt_balance(&sig, &vault, balance);
//         let amount = decrypt_balance(&sig, &vault, cipher);
//         println!("{:?}", amount);
//     }
// }