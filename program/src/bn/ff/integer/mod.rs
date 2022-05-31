#[macro_use]
mod arithmetic;
#[macro_use]
mod macros;

pub use arithmetic::*;
pub use macros::*;

use std::fmt::Debug;
use borsh::{BorshSerialize, BorshDeserialize};
use serde::{Serialize, Deserialize};

bigint_impl!(BigInteger256, 4);

/// This defines a `BigInteger`, a smart wrapper around a
/// sequence of `u64` limbs, least-significant limb first.
pub trait BigInteger:
    'static
    + Debug
    + Copy
    + Clone
    + Default
    + Eq
    + Ord
    + Sized
    + AsMut<[u64]>
    + AsRef<[u64]>
    + From<u64>
    + BorshSerialize
    + BorshDeserialize
    + Serialize
    + Deserialize<'static>
{
    /// Number of limbs.
    const NUM_LIMBS: usize;

    /// Add another representation to this one, returning the carry bit.
    fn add_nocarry(&mut self, other: &Self) -> bool;

    /// Subtract another representation from this one, returning the borrow bit.
    fn sub_noborrow(&mut self, other: &Self) -> bool;

    /// Performs a leftwise bitshift of this number, effectively multiplying
    /// it by 2. Overflow is ignored.
    fn mul2(&mut self);

    /// Performs a leftwise bitshift of this number by some amount.
    fn muln(&mut self, amt: u32);

    /// Performs a rightwise bitshift of this number, effectively dividing
    /// it by 2.
    fn div2(&mut self);

    /// Performs a rightwise bitshift of this number by some amount.
    fn divn(&mut self, amt: u32);

    /// Returns true iff this number is odd.
    fn is_odd(&self) -> bool;

    /// Returns true iff this number is even.
    fn is_even(&self) -> bool;

    /// Returns true iff this number is zero.
    fn is_zero(&self) -> bool;

    /// Compute the number of bits needed to encode this number. Always a
    /// multiple of 64.
    fn num_bits(&self) -> u32;

    /// Compute the `i`-th bit of `self`.
    fn get_bit(&self, i: usize) -> bool;

    /// Returns the byte representation in a big endian byte array,
    /// with leading zeros.
    fn to_bytes_be(&self) -> Vec<u8>;

    /// Returns the byte representation in a little endian byte array,
    /// with trailing zeros.
    fn to_bytes_le(&self) -> Vec<u8>;
}

