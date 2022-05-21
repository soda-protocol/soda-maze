use arrayref::array_refs;
use solana_program::pubkey::Pubkey;

use crate::bn::BigInteger256 as BigInteger;
use crate::params::bn::Fr;

#[inline]
pub fn pubkey_to_fr(pubkey: Pubkey) -> Fr {
    let pubkey = &pubkey.to_bytes();
    let (d0, d1, d2, d3) = array_refs![pubkey, 8, 8, 8, 8];    
    let repr = [
        u64::from_le_bytes(*d0),
        u64::from_le_bytes(*d1),
        u64::from_le_bytes(*d2),
        u64::from_le_bytes(*d3) & ((1u64 << 61) - 1),
    ];

    Fr::from_repr(BigInteger::new(repr)).unwrap()
}