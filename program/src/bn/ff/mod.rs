mod model;
mod integer;
#[macro_use]
mod macros;
#[macro_use]
mod arithmetic;

use borsh::{BorshSerialize, BorshDeserialize};
pub use model::*;
pub use integer::*;

use crate::{adc, mac_with_carry};

use core::ops::{Neg, Add, Sub, Mul, AddAssign, SubAssign, MulAssign};
use num_traits::{Zero, One};

impl_Fp!(
    Fp256,
    Fp256Parameters,
    BigInteger256,
    BigInteger256,
    4,
    "256"
);

pub trait Field:
    'static
    + Copy
    + Clone
    + Eq
    + Zero
    + One
    + Neg<Output = Self>
    + Sized
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + BorshSerialize
    + BorshDeserialize
{
    /// Returns the characteristic of the field,
    /// in little-endian representation.
    fn characteristic() -> &'static [u64];

    /// Returns the extension degree of this field with respect
    /// to `Self::BasePrimeField`.
    fn extension_degree() -> u64;

    /// Returns `self + self`.
    #[must_use]
    fn double(&self) -> Self;

    /// Doubles `self` in place.
    fn double_in_place(&mut self) -> &mut Self;

    /// Returns `self * self`.
    #[must_use]
    fn square(&self) -> Self;

    /// Squares `self` in place.
    fn square_in_place(&mut self) -> &mut Self;

    /// Computes the multiplicative inverse of `self` if `self` is nonzero.
    #[must_use]
    fn inverse(&self) -> Option<Self>;

    /// Exponentiates this element by a power of the base prime modulus via
    /// the Frobenius automorphism.
    fn frobenius_map(&mut self, power: usize);
}

/// A trait that defines parameters for a prime field.
pub trait FpParameters: 'static {
    type BigInteger: BigInteger;

    /// The modulus of the field.
    const MODULUS: Self::BigInteger;

    /// The number of bits needed to represent the `Self::MODULUS`.
    const MODULUS_BITS: u32;

    /// The number of bits that must be shaved from the beginning of
    /// the representation when randomly sampling.
    const REPR_SHAVE_BITS: u32;

    /// Let `M` be the power of 2^64 nearest to `Self::MODULUS_BITS`. Then
    /// `R = M % Self::MODULUS`.
    const R: Self::BigInteger;

    /// R2 = R^2 % Self::MODULUS
    const R2: Self::BigInteger;

    /// INV = -MODULUS^{-1} mod 2^64
    const INV: u64;

    /// A multiplicative generator of the field.
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`.
    const GENERATOR: Self::BigInteger;

    /// The number of bits that can be reliably stored.
    /// (Should equal `SELF::MODULUS_BITS - 1`)
    const CAPACITY: u32;

    /// t for 2^s * t = MODULUS - 1, and t coprime to 2.
    const T: Self::BigInteger;

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: Self::BigInteger;

    /// (Self::MODULUS - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInteger;
}

/// Iterates over a slice of `u64` in *big-endian* order.
#[derive(Debug)]
pub struct BitIteratorBE<Slice: AsRef<[u64]>> {
    s: Slice,
    n: usize,
}

impl<Slice: AsRef<[u64]>> BitIteratorBE<Slice> {
    pub fn new(s: Slice) -> Self {
        let n = s.as_ref().len() * 64;
        BitIteratorBE { s, n }
    }

    /// Construct an iterator that automatically skips any leading zeros.
    /// That is, it skips all zeros before the most-significant one.
    pub fn without_leading_zeros(s: Slice) -> impl Iterator<Item = bool> {
        Self::new(s).skip_while(|b| !b)
    }
}

impl<Slice: AsRef<[u64]>> Iterator for BitIteratorBE<Slice> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 64;
            let bit = self.n - (64 * part);

            Some(self.s.as_ref()[part] & (1 << bit) > 0)
        }
    }
}
