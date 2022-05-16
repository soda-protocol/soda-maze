mod encrypt;

pub use encrypt::*;

use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;
use num_integer::Integer;

pub fn biguint_to_biguint_array(u: BigUint, len: usize, bit_size: usize) -> Vec<BigUint> {
    let mut array = Vec::with_capacity(len);
    let mut rest = u;
    let base = BigUint::from(1u64) << bit_size;
    for _ in 0..len {
        let (hi, lo) = rest.div_rem(&base);
        rest = hi;
        array.push(lo);
    }
    assert_eq!(rest, BigUint::from(0u64));

    array
}

pub fn prime_field_partly_to_biguint_array<F: PrimeField>(v: F, len: usize, bit_size: usize) -> Vec<BigUint> {
    assert!(len * bit_size <= F::Params::MODULUS_BITS as usize);
    biguint_to_biguint_array(v.into(), len, bit_size)
}

pub fn prime_field_to_biguint_array<F: PrimeField>(v: F, bit_size: usize) -> Vec<BigUint> {
    let mut len = F::Params::MODULUS_BITS as usize / bit_size;
    if F::Params::MODULUS_BITS as usize % bit_size != 0 {
        len += 1;
    }
    biguint_to_biguint_array(v.into(), len, bit_size)
}

pub fn biguint_array_to_biguint(array: &[BigUint], bit_size: usize) -> BigUint {
    let (out, _) = array.into_iter().fold(
        (BigUint::from(0u64), BigUint::from(1u64)),
        |(value, base), p| {
            assert!(p.bits() as usize <= bit_size);
            let value = value + &base * p;
            let base = base << bit_size;
            (value, base)
        });

    out
}