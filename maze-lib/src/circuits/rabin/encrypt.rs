use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use num_bigint::BigUint;
use lazy_static::lazy_static;

use super::uint::GeneralUint;
use super::poly::*;

pub const BIT_SIZE: u64 = 124;
pub const PRIME_LENGTH: usize = 12;
pub const MODULUS_LENGTH: usize = PRIME_LENGTH * 2;

lazy_static! {
    pub static ref MODULUS: BigUint = BigUint::from_bytes_le(&[
        197, 5, 157, 205, 195, 73, 203, 233, 6, 228, 253, 111,
        87, 231, 14, 83, 132, 129, 101, 166, 204, 166, 230, 81,
        28, 119, 234, 2, 105, 143, 160, 10, 93, 24, 15, 171, 186,
        228, 217, 92, 180, 163, 84, 171, 144, 67, 203, 146, 41, 30,
        105, 95, 183, 210, 85, 145, 34, 111, 216, 107, 192, 13, 223,
        152, 243, 149, 106, 235, 23, 205, 163, 153, 130, 218, 69,
        103, 79, 181, 210, 228, 117, 157, 191, 50, 20, 178, 140,
        225, 148, 84, 46, 243, 108, 240, 115, 101, 205, 92, 229,
        233, 182, 29, 14, 6, 180, 42, 53, 6, 52, 23, 36, 113, 85,
        223, 103, 141, 33, 15, 227, 130, 168, 128, 230, 29, 218,
        119, 73, 58, 180, 68, 236, 31, 65, 234, 87, 168, 51, 76,
        43, 195, 18, 186, 36, 20, 155, 245, 161, 13, 157, 210, 4,
        148, 245, 9, 214, 137, 18, 170, 219, 242, 177, 130, 158,
        186, 167, 253, 94, 163, 79, 115, 210, 157, 190, 111, 73,
        54, 53, 236, 232, 224, 40, 93, 137, 83, 169, 123, 108, 46,
        41, 47, 74, 168, 197, 210, 112, 59, 31, 84, 22, 55, 39, 30,
        148, 119, 197, 207, 233, 159, 21, 9, 34, 226, 3, 98, 37,
        249, 32, 143, 182, 165, 19, 81, 141, 108, 188, 125, 225,
        164, 211, 203, 221, 174, 127, 145, 146, 50, 147, 138, 201,
        84, 54, 102, 113, 212, 136, 251, 141, 6, 78, 245, 46, 80,
        181, 199, 143, 39, 73, 41, 198, 59, 104, 226, 209, 181, 35,
        37, 186, 176, 81, 87, 200, 100, 234, 190, 95, 3, 64, 46, 205,
        195, 154, 227, 118, 139, 197, 191, 82, 186, 229, 214, 87, 71,
        219, 79, 109, 85, 158, 102, 151, 26, 19, 95, 228, 14, 54, 154,
        26, 249, 41, 97, 252, 242, 200, 24, 47, 80, 187, 94, 193, 206,
        65, 187, 22, 199, 87, 76, 86, 131, 51, 116, 206, 68, 41, 180, 6,
        42, 150, 111, 89, 69, 4, 67, 59, 214, 73, 205, 51, 153, 212, 4,
        217, 62, 4, 11, 222, 8, 182, 17, 20, 11, 251, 166, 251, 215,
        188, 153, 0, 118, 122, 95, 207, 177,
    ]);
}

fn poly_array_to_biguint<F: PrimeField, const BIT_SIZE: u64>(
    preimage: &[GeneralUint<F>],
) -> Result<BigUint, SynthesisError> {
    let base = BigUint::from(1u64) << BIT_SIZE;
    preimage.iter().try_fold(BigUint::from(0u64), |value, p| {
        Ok(&base * p.value()? + value)
    })
}

pub fn biguint_to_const_poly_array<F: PrimeField, const BIT_SIZE: u64, const MODULUS_LENGTH: usize>(
    value: &BigUint,
) -> Vec<GeneralUint<F>> {
    let ref mask = (BigUint::from(1u64) << BIT_SIZE) - BigUint::from(1u64);
    (0..MODULUS_LENGTH).into_iter().map(|i| {
        let tmp = (value >> (BIT_SIZE as usize * i)) & mask;
        GeneralUint::new_constant(tmp)
    }).collect::<Vec<_>>()
}

// preimage = leaf | leaf | ... | 0 | ... | 0
pub fn generate_preimage_from_fp_var<F: PrimeField, const BIT_SIZE: u64, const MODULUS_LENGTH: usize>(
    leaf: FpVar<F>,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    let leaf_array = GeneralUint::from_fp_var::<BIT_SIZE>(leaf)?;
    let mut res = Vec::with_capacity(MODULUS_LENGTH);
    for _ in 0..MODULUS_LENGTH / leaf_array.len() {
        res.extend_from_slice(&leaf_array);
    }
    for _ in 0..MODULUS_LENGTH % leaf_array.len() {
        res.push(GeneralUint::zero());
    }
    let preimage_uint = poly_array_to_biguint::<_, BIT_SIZE>(&res)?;
    assert!(&preimage_uint < &MODULUS);

    Ok(res)
}

pub fn generate_cypher_from_fp_var<F: PrimeField, const BIT_SIZE: u64, const MODULUS_LENGTH: usize>(
    cypher: Vec<FpVar<F>>,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    let res = cypher.into_iter()
        .map(|c| GeneralUint::from_fp_var::<BIT_SIZE>(c))
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(res.len(), MODULUS_LENGTH);

    Ok(res)
}

pub fn rabin_encryption<F: PrimeField>(
    modulus: &[GeneralUint<F>],
    preimage: &[GeneralUint<F>],
    quotient: &[GeneralUint<F>],
    cypher: Vec<GeneralUint<F>>,
) -> Result<(), SynthesisError> {
    assert_eq!(preimage.len(), MODULUS_LENGTH);
    assert_eq!(quotient.len(), MODULUS_LENGTH);
    assert_eq!(cypher.len(), MODULUS_LENGTH);

    // verify: quotient * modulus + cypher = preimage^2
    let product = polynomial_mul::<_, BIT_SIZE>(quotient, modulus)?;
    let (carry, sum) = polynomial_add::<_, BIT_SIZE>(product, cypher)?;
    carry.force_equal(&GeneralUint::zero())?;

    let preimage_square = polynomial_square::<_, BIT_SIZE>(preimage)?;
    polynomial_force_equal(&sum, &preimage_square)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use num_integer::Integer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    // use num_bigint_dig::{RandPrime, BigUint};
    use num_bigint::BigUint;

    use crate::circuits::encrypt::biguint_to_const_poly_array;

    use super::{MODULUS_LENGTH, MODULUS, GeneralUint, BIT_SIZE, rabin_encryption};

    fn get_rand_fr(rng: &mut StdRng) -> Fr {
        Fr::rand(rng)
    }

    fn poly_array_to_biguint(poly: &[BigUint]) -> BigUint {
        let mut base = BigUint::from(1u64);
        let mut res = BigUint::from(0u64);
        for p in poly.iter() {
            res += &base * p;
            base *= BigUint::from(1u128 << BIT_SIZE);
        }
        res
    }

    fn biguint_to_poly_array(mut x: BigUint) -> Vec<BigUint> {
        let base = BigUint::from(1u128 << BIT_SIZE);
        let mut res = Vec::new();
        for _ in 0..MODULUS_LENGTH {
            let (hi, lo) = x.div_rem(&base);
            res.push(lo);
            x = hi;
        }
        res
    }

    fn get_random_preimage(rng: &mut StdRng) -> Vec<BigUint> {
        (0..MODULUS_LENGTH)
            .into_iter()
            .map(|_| {
                let mut v = u128::rand(rng);
                v &= (1u128 << 124) - 1;

                BigUint::from(v)
            }).collect()
    }

    #[test]
    fn test_prime_key() {
        let rng = &mut test_rng();

        use num_bigint_dig::RandPrime;

        let p = rng.gen_prime(1488);
        let q = rng.gen_prime(1488);
        let ref n = p * q;

        println!("{:?}", n.to_bytes_le());
    }

    #[test]
    fn test_verify_rabin_encryption() {
        let rng = &mut test_rng();
        let preimage = get_random_preimage(rng);

        let modulus = &MODULUS;
        let raw_preimage = poly_array_to_biguint(&preimage);
        let raw_preimage_square = &raw_preimage * &raw_preimage;
        let (quotient_raw, cypher_raw) = raw_preimage_square.div_rem(modulus);

        let quotient = biguint_to_poly_array(quotient_raw);
        let cypher = biguint_to_poly_array(cypher_raw);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let preimage = preimage.into_iter().map(|p| {
            GeneralUint::new_witness(cs.clone(), || Ok(p), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();
        let quotient = quotient.into_iter().map(|q| {
            GeneralUint::new_witness(cs.clone(), || Ok(q), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();
        let cypher = cypher.into_iter().map(|c| {
            GeneralUint::new_witness(cs.clone(), || Ok(c), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();
        let modulus = biguint_to_const_poly_array(&MODULUS);

        rabin_encryption(&modulus, &preimage, &quotient, cypher).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}