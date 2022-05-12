use ark_ff::{PrimeField, FpParameters};
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use num_bigint::BigUint;

use super::uint::GeneralUint;
use super::poly::*;

fn poly_array_to_biguint<F: PrimeField>(
    preimage: &[GeneralUint<F>],
    bit_size: u64,
) -> Result<BigUint, SynthesisError> {
    let (res, _) = preimage.iter().try_fold(
        (BigUint::from(0u64), BigUint::from(1u64)),
        |(value, base), p| {
            let value = value + &base * p.value()?;
            let base = base << bit_size;

            Ok((value, base))
        })?;

    Ok(res)
}

// preimage = leaf | leaf | ... | 0 | ... | 0
fn gen_preimage_from_fp_var<F: PrimeField>(
    leaf: FpVar<F>,
    modulus: &[GeneralUint<F>],
    bit_size: u64,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    let leaf_array = GeneralUint::split_fp_var(leaf, bit_size)?;
    let mut res = Vec::with_capacity(modulus.len());
    for _ in 0..modulus.len() / leaf_array.len() {
        res.extend_from_slice(&leaf_array);
    }
    for _ in 0..modulus.len() % leaf_array.len() {
        res.push(GeneralUint::zero());
    }
    let preimage_uint = poly_array_to_biguint(&res, bit_size)?;
    let modulus_uint = poly_array_to_biguint(modulus, bit_size)?;
    assert!(preimage_uint < modulus_uint);

    Ok(res)
}

fn gen_cypher_from_fp_var<F: PrimeField>(
    cypher: Vec<FpVar<F>>,
    bit_size: u64,
    cypher_batch_size: usize,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    let cypher = cypher.into_iter()
        .map(|c| GeneralUint::partly_split_fp_var(c, bit_size, cypher_batch_size))
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    Ok(cypher)
}

fn rabin_encrypt<F: PrimeField>(
    modulus: &[GeneralUint<F>],
    preimage: &[GeneralUint<F>],
    quotient: &[GeneralUint<F>],
    cypher: Vec<GeneralUint<F>>,
    bit_size: u64,
) -> Result<(), SynthesisError> {
    // quotient * modulus + cypher = preimage^2
    let product = polynomial_mul(quotient, modulus, bit_size)?;
    let (carry, sum) = polynomial_add(product, cypher, bit_size)?;
    carry.force_equal(&GeneralUint::zero())?;

    let preimage_square = polynomial_square(preimage, bit_size)?;
    polynomial_force_equal(&sum, &preimage_square)?;

    Ok(())
}

pub struct RabinEncryption<F: PrimeField> {
    modulus: Vec<BigUint>,
    quotient: Vec<BigUint>,
    cypher: Vec<F>,
    bit_size: u64,
    cypher_batch_size: usize,
}

impl<F: PrimeField> RabinEncryption<F> {
    pub fn new(
        modulus: Vec<BigUint>,
        quotient: Vec<BigUint>,
        cypher: Vec<F>,
        bit_size: u64,
        cypher_batch_size: usize,
    ) -> Self {
        assert_eq!(modulus.len(), quotient.len());
        modulus.iter().zip(quotient.iter()).for_each(|(m, q)| {
            assert!(m.bits() <= bit_size);
            assert!(q.bits() <= bit_size);
        });
        assert!(cypher_batch_size as u64 * bit_size < F::Params::MODULUS_BITS as u64);
        assert_eq!(modulus.len() % cypher_batch_size as usize, 0);

        Self {
            modulus,
            quotient,
            cypher,
            bit_size,
            cypher_batch_size,
        }
    }

    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<F>,
        leaf_var: FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // alloc constant
        let modulus = self.modulus
            .into_iter()
            .map(|m| GeneralUint::new_constant(m))
            .collect::<Vec<_>>();
        // alloc input
        let fp_cypher = self.cypher
            .into_iter()
            .map(|v| FpVar::new_input(cs.clone(), || Ok(v)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        // alloc private
        let quotient = self.quotient
            .into_iter()
            .map(|m| GeneralUint::new_witness(cs.clone(), || Ok(m), self.bit_size))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // transform fp leaf to preimage
        let preimage = gen_preimage_from_fp_var(
            leaf_var,
            &modulus,
            self.bit_size,
        )?;
        // transform fp cypher to general uint
        let cypher = gen_cypher_from_fp_var(fp_cypher, self.bit_size, self.cypher_batch_size)?;
        // encryption
        rabin_encrypt(&modulus, &preimage, &quotient, cypher, self.bit_size)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, FpParameters};
    use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use num_bigint::BigUint;
    use num_integer::Integer;
    use lazy_static::lazy_static;

    use super::{GeneralUint, rabin_encrypt, gen_preimage_from_fp_var, gen_cypher_from_fp_var, RabinEncryption};
    
    const BIT_SIZE: u64 = 124;
    const CYPHER_BATCH_SIZE: usize = 2;
    const PRIME_LENGTH: usize = 12;
    const MODULUS_LEN: usize = PRIME_LENGTH * 2;
    
    lazy_static! {
        static ref MODULUS: BigUint = BigUint::from_bytes_le(&[
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

    fn get_rand_fr(rng: &mut StdRng) -> Fr {
        Fr::rand(rng)
    }

    fn get_preimage_from_leaf(leaf: Fr) -> BigUint {
        let leaf_uint: BigUint = leaf.into();
        let modulus_bits = <Fr as PrimeField>::Params::MODULUS_BITS as usize;
        let mut f_bits = modulus_bits / (BIT_SIZE as usize);
        if modulus_bits % (BIT_SIZE as usize) != 0 {
            f_bits += 1;
        }
    
        let mut preimage = leaf_uint.clone();
        for _ in 1..MODULUS_LEN / f_bits {
            preimage <<= BIT_SIZE as usize * f_bits;
            preimage += &leaf_uint;
        }
        assert!(&preimage < &MODULUS);
    
        preimage
    }

    pub fn gen_cypher_array(cypher: BigUint) -> Vec<Fr> {
        let cypher_bits = CYPHER_BATCH_SIZE * (BIT_SIZE as usize);
        assert!(cypher_bits < <Fr as PrimeField>::Params::MODULUS_BITS as usize);
        assert_eq!(MODULUS_LEN % CYPHER_BATCH_SIZE, 0);

        let base = BigUint::from(1u64) << cypher_bits;
        let mut rest = cypher;
    
        let res = (0..MODULUS_LEN / CYPHER_BATCH_SIZE).into_iter().map(|_| {
            let (hi, lo) = rest.div_rem(&base);
            rest = hi;
            Fr::from(lo)
        }).collect::<Vec<_>>();
        assert_eq!(rest, BigUint::from(0u64));
    
        res
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

    fn biguint_to_poly_array(x: &BigUint) -> Vec<BigUint> {
        let base = BigUint::from(1u128 << BIT_SIZE);
        let mut rest = x.clone();
        let mut res = Vec::new();
        for _ in 0..MODULUS_LEN {
            let (hi, lo) = rest.div_rem(&base);
            res.push(lo);
            rest = hi;
        }
        res
    }

    fn get_random_uint_array(rng: &mut StdRng) -> Vec<BigUint> {
        let mut res = (0..MODULUS_LEN-1)
            .into_iter()
            .map(|_| {
                let mut v = u128::rand(rng);
                v &= (1u128 << 124) - 1;

                BigUint::from(v)
            }).collect::<Vec<_>>();
        res.push(BigUint::from(1u64));

        res
    }

    #[test]
    fn test_get_modulus() {
        let rng = &mut test_rng();

        use num_bigint_dig::RandPrime;

        let p = rng.gen_prime(BIT_SIZE as usize * PRIME_LENGTH);
        let q = rng.gen_prime(BIT_SIZE as usize * PRIME_LENGTH);
        let ref n = p * q;

        println!("{:?}", n.to_bytes_le());
    }

    #[test]
    fn test_gen_preimage_from_fp_var() {
        let rng = &mut test_rng();
        let modulus = biguint_to_poly_array(&MODULUS);
        let leaf = get_rand_fr(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let modulus = modulus.into_iter().map(|m| {
            GeneralUint::new_constant(m)
        }).collect::<Vec<_>>();
        let leaf = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();

        let _ = gen_preimage_from_fp_var(leaf, &modulus, BIT_SIZE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_gen_cypher_from_fp_var() {
        let rng = &mut test_rng();
        let cypher = get_random_uint_array(rng);
        let cypher = cypher.chunks_exact(2).map(|batch| {
            let res = &batch[0] + &batch[1] * BigUint::from(1u128 << BIT_SIZE);
            res.into()
        }).collect::<Vec<Fr>>();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let cypher = cypher.into_iter().map(|c| {
            FpVar::new_input(cs.clone(), || Ok(c)).unwrap()
        }).collect::<Vec<_>>();

        let _ = gen_cypher_from_fp_var(cypher, BIT_SIZE, CYPHER_BATCH_SIZE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_rabin_encryption() {
        let rng = &mut test_rng();
        let preimage = get_random_uint_array(rng);

        let raw_preimage = poly_array_to_biguint(&preimage);
        let raw_preimage_square = &raw_preimage * &raw_preimage;
        let (quotient_raw, cypher_raw) = raw_preimage_square.div_rem(&MODULUS);

        let quotient = biguint_to_poly_array(&quotient_raw);
        let cypher = biguint_to_poly_array(&cypher_raw);
        let modulus = biguint_to_poly_array(&MODULUS);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let modulus = modulus.into_iter().map(|m| {
            GeneralUint::new_constant(m)
        }).collect::<Vec<_>>();
        let preimage = preimage.into_iter().map(|p| {
            GeneralUint::new_witness(cs.clone(), || Ok(p), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();
        let quotient = quotient.into_iter().map(|q| {
            GeneralUint::new_witness(cs.clone(), || Ok(q), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();
        let cypher = cypher.into_iter().map(|c| {
            GeneralUint::new_witness(cs.clone(), || Ok(c), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();

        rabin_encrypt(&modulus, &preimage, &quotient, cypher, BIT_SIZE).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_rabin_encryption_synthesize() {
        let rng = &mut test_rng();
        let leaf = get_rand_fr(rng);

        let preimage = get_preimage_from_leaf(leaf);
        let (quotient, cypher) = (&preimage * &preimage).div_rem(&MODULUS);

        let quotient = biguint_to_poly_array(&quotient);
        let cypher = gen_cypher_array(cypher);
        let modulus = biguint_to_poly_array(&MODULUS);

        let rabin_encryption = RabinEncryption::<Fr>::new(
            modulus,
            quotient,
            cypher,
            BIT_SIZE,
            CYPHER_BATCH_SIZE,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let leaf_var = FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap();
        rabin_encryption.synthesize(cs.clone(), leaf_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}