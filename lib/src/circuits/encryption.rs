use std::{marker::PhantomData, rc::Rc};
use ark_ff::{PrimeField, FpParameters};
use ark_r1cs_std::{fields::fp::{FpVar, AllocatedFp}, alloc::AllocVar, prelude::EqGadget};
use ark_relations::{lc, r1cs::{ConstraintSystemRef, LinearCombination, Variable, ConstraintSynthesizer, Result}};
use num_bigint::BigUint;

use crate::vanilla::{hasher::FieldHasher, biguint::prime_field_partly_to_biguint_array};
use super::FieldHasherGadget;
use super::biguint::*;

fn gen_preimage_array<F: PrimeField>(
    nullifier_array: Vec<GeneralUint<F>>,
    nullifier_field: FpVar<F>,
    padding_array: Vec<GeneralUint<F>>,
    bit_size: usize,
) -> Result<Vec<GeneralUint<F>>> {
    let base = BigUint::from(1u64) << bit_size;
    let base_field = F::from(base.clone());

    let (lc, _) = nullifier_array
        .iter()
        .try_fold((lc!(), F::one()), |(lc, coeff), var| {
            let lc = lc + (coeff, var.variable()?);
            Ok((lc, coeff * base_field))
        })?;
    if let FpVar::Var(nullifier) = nullifier_field {
        nullifier.cs.enforce_constraint(
            LinearCombination::from(nullifier.variable),
            LinearCombination::from(Variable::One),
            lc,
        )?;
    }

    // preimage = ... rand ... | nullifier
    let mut preimage_array = padding_array;
    preimage_array.extend(nullifier_array);

    Ok(preimage_array)
}

fn gen_cipher_array<F: PrimeField>(
    cipher_uint_array: Vec<Vec<GeneralUint<F>>>,
    cipher_field_array: Vec<AllocatedFp<F>>,
    bit_size: usize,
) -> Result<Vec<GeneralUint<F>>> {
    let base = BigUint::from(1u64) << bit_size;
    let base_field = F::from(base.clone());

    // constrain cipher uint array
    cipher_uint_array.iter()
        .zip(cipher_field_array)
        .try_for_each(|(array, cipher)| {    
            let (lc, _) = array.iter()
                .try_fold((lc!(), F::one()), |(lc, coeff), cipher| {
                    let lc = lc + (coeff, cipher.variable()?);
                    Ok((lc, coeff * base_field))
                })?;

            cipher.cs.enforce_constraint(
                LinearCombination::from(cipher.variable),
                LinearCombination::from(Variable::One),
                lc,
            )
        })?;

    let cipher_array = cipher_uint_array.into_iter().flatten().collect::<Vec<_>>();
    Ok(cipher_array)
}

fn rabin_encrypt<F: PrimeField>(
    modulus: Vec<GeneralUint<F>>,
    preimage: Vec<GeneralUint<F>>,
    quotient: Vec<GeneralUint<F>>,
    cipher: Vec<GeneralUint<F>>,
    bit_size: usize,
) -> Result<()> {
    // quotient * modulus + cipher = preimage^2
    let product = polynomial_mul(&quotient, &modulus, bit_size)?;
    let (carry, sum) = polynomial_add(product, cipher, bit_size)?;
    carry.force_equal(&GeneralUint::zero())?;

    let preimage_square = polynomial_square(&preimage, bit_size)?;
    polynomial_force_equal(&sum, &preimage_square)?;

    Ok(())
}

pub struct EncryptionCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    commitment_params: Rc<FH::Parameters>,
    nullifier_params: Rc<FH::Parameters>,
    modulus_array: Vec<BigUint>,
    quotient_array: Vec<BigUint>,
    padding_array: Vec<BigUint>,
    cipher_field_array: Vec<F>,
    nullifier_array: Vec<BigUint>,
    leaf_index: u64,
    secret: F,
    commitment: F,
    bit_size: usize,
    cipher_batch: usize,
    _h: PhantomData<FHG>,
}

impl<F, FH, FHG> ConstraintSynthesizer<F> for EncryptionCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        // alloc constant
        let commitment_params = FHG::ParametersVar::new_constant(cs.clone(), self.commitment_params)?;
        let nullifier_params = FHG::ParametersVar::new_constant(cs.clone(), self.nullifier_params)?;
        let modulus_array = self.modulus_array
            .into_iter()
            .map(|m| GeneralUint::new_constant(m))
            .collect::<Vec<_>>();
        
        // alloc input
        let index = FpVar::new_input(cs.clone(), || Ok(F::from(self.leaf_index)))?;
        let commitment_input = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        let cipher_field_array = self.cipher_field_array
            .iter()
            .map(|v| AllocatedFp::new_input(cs.clone(), || Ok(*v)))
            .collect::<Result<Vec<_>>>()?;
        
        // alloc private
        let secret = AllocatedFp::new_witness(cs.clone(), || Ok(self.secret))?;
        let quotient_array = self.quotient_array
            .into_iter()
            .map(|m| GeneralUint::new_witness(cs.clone(), || Ok(m), self.bit_size))
            .collect::<Result<Vec<_>>>()?;
        let padding_array = self.padding_array
            .into_iter()
            .map(|p| GeneralUint::new_witness(cs.clone(), || Ok(p), self.bit_size))
            .collect::<Result<Vec<_>>>()?;
        let cipher_uint_array = self.cipher_field_array
            .into_iter()
            .map(|c| {
                let cipher = prime_field_partly_to_biguint_array::<F>(
                    c,
                    self.cipher_batch,
                    self.bit_size,
                );
                cipher.into_iter().map(|c| {
                    GeneralUint::new_witness(cs.clone(), || Ok(c), self.bit_size)
                }).collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let nullifier_array = {
            let mut size_array = (0..F::Params::MODULUS_BITS as usize / self.bit_size)
                .into_iter()
                .map(|_| self.bit_size)
                .collect::<Vec<_>>();
            let bit_size = F::Params::MODULUS_BITS as usize % self.bit_size;
            if F::Params::MODULUS_BITS as usize % self.bit_size != 0 {
                size_array.push(bit_size);
            }
            size_array.into_iter()
                .zip(self.nullifier_array)
                .map(|(bit_size, nullifier)| {
                    GeneralUint::new_witness(cs.clone(), || Ok(nullifier), bit_size)
                })
                .collect::<Result<Vec<_>>>()?
        };

        // hash for commitment
        let commitment = FHG::hash_gadget(
            &commitment_params,
            &[secret.clone().into()],
        )?;
        commitment.enforce_equal(&commitment_input)?;

        // hash for nullifier
        let nullifier = FHG::hash_gadget(
            &nullifier_params,
            &[index.clone(), secret.into()],
        )?;

        // gen preimage array
        let preimage_array = gen_preimage_array(
            nullifier_array,
            nullifier,
            padding_array,
            self.bit_size,
        )?;
        assert_eq!(preimage_array.len(), modulus_array.len());

        // gen cipher array
        let cipher_array = gen_cipher_array(
            cipher_uint_array,
            cipher_field_array,
            self.bit_size,
        )?;
        assert_eq!(cipher_array.len(), modulus_array.len());

        rabin_encrypt(
            modulus_array,
            preimage_array,
            quotient_array,
            cipher_array,
            self.bit_size,
        )
    }
}

impl<F, FH, FHG> EncryptionCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment_params: FH::Parameters,
        nullifier_params: FH::Parameters,
        modulus_array: Vec<BigUint>,
        bit_size: usize,
        cipher_batch: usize,
        leaf_index: u64,
        commitment: F,
        cipher_field_array: Vec<F>,
        secret: F,
        quotient_array: Vec<BigUint>,
        padding_array: Vec<BigUint>,
        nullifier_array: Vec<BigUint>,
    ) -> Self {
        Self {
            commitment_params: Rc::new(commitment_params),
            nullifier_params: Rc::new(nullifier_params),
            modulus_array,
            quotient_array,
            padding_array,
            cipher_field_array,
            nullifier_array,
            leaf_index,
            secret,
            commitment,
            bit_size,
            cipher_batch,
            _h: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, FpParameters};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
    use arkworks_utils::utils::common::{Curve, setup_params_x5_3};
    use ark_std::{test_rng, UniformRand, rand::{prelude::StdRng, Rng}};
    use arkworks_utils::utils::common::setup_params_x5_2;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use lazy_static::lazy_static;

    use crate::vanilla::{biguint::*, hasher::{poseidon::PoseidonHasher, FieldHasher}};
    use crate::circuits::poseidon::PoseidonHasherGadget;
    use super::{GeneralUint, rabin_encrypt, EncryptionCircuit};
    
    const BIT_SIZE: usize = 124;
    const CIPHER_BATCH: usize = 2;
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

    fn get_rand_fr<R: Rng + ?Sized>(rng: &mut R) -> Fr {
        Fr::rand(rng)
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

    fn gen_preimage_from_nullifier<R: Rng + ?Sized>(rng: &mut R, nullifier_array: &[BigUint]) -> (BigUint, Vec<BigUint>) {
        let mut nullifier_len = <Fr as PrimeField>::Params::MODULUS_BITS as usize / BIT_SIZE;
        if <Fr as PrimeField>::Params::MODULUS_BITS as usize % BIT_SIZE != 0 {
            nullifier_len += 1;
        }
        
        let mut padding = Vec::with_capacity(MODULUS_LEN - nullifier_len);
        for _ in 0..MODULUS_LEN - nullifier_len {
            let mut v = u128::rand(rng);
            v &= (1u128 << 124) - 1;

            padding.push(BigUint::from(v));
        }

        let preimage = vec![&padding[..], &nullifier_array[..]].concat();
        let preimage = biguint_array_to_biguint(&preimage, BIT_SIZE);

        (preimage, padding)
    }

    fn gen_cipher_field_array(cipher: BigUint) -> Vec<Fr> {
        let cipher_bits = CIPHER_BATCH * BIT_SIZE;
        assert!(cipher_bits < <Fr as PrimeField>::Params::MODULUS_BITS as usize);
        let cipher_array = biguint_to_biguint_array(
            cipher,
            MODULUS_LEN / CIPHER_BATCH,
            cipher_bits,
        );
        cipher_array.into_iter().map(|c| c.into()).collect()
    }

    #[test]
    fn test_get_modulus() {
        let rng = &mut test_rng();

        use num_bigint_dig::RandPrime;

        let p = rng.gen_prime(BIT_SIZE * PRIME_LENGTH);
        let q = rng.gen_prime(BIT_SIZE * PRIME_LENGTH);
        let ref n = p * q;

        println!("{:?}", n.to_bytes_le());
    }

    #[test]
    fn test_rabin_encryption() {
        let rng = &mut test_rng();
        let preimage = get_random_uint_array(rng);

        let raw_preimage = biguint_array_to_biguint(&preimage, BIT_SIZE);
        let raw_preimage_square = &raw_preimage * &raw_preimage;
        let (quotient_raw, cipher_raw) = raw_preimage_square.div_rem(&MODULUS);

        let quotient = biguint_to_biguint_array(quotient_raw, MODULUS_LEN, BIT_SIZE);
        let cipher = biguint_to_biguint_array(cipher_raw, MODULUS_LEN, BIT_SIZE);
        let modulus = biguint_to_biguint_array(MODULUS.clone(), MODULUS_LEN, BIT_SIZE);

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
        let cipher = cipher.into_iter().map(|c| {
            GeneralUint::new_witness(cs.clone(), || Ok(c), BIT_SIZE).unwrap()
        }).collect::<Vec<_>>();

        rabin_encrypt(modulus, preimage, quotient, cipher, BIT_SIZE).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_rabin_encryption_synthesize() {
        let commitment_params = setup_params_x5_2(Curve::Bn254);
        let nullifier_params = setup_params_x5_3(Curve::Bn254);

        let rng = &mut test_rng();
        let leaf_index = u64::rand(rng);
        let secret = get_rand_fr(rng);
        let commitment = PoseidonHasher::hash(
            &commitment_params,
            &[secret],
        ).unwrap();
        let nullifier = PoseidonHasher::hash(
            &nullifier_params,
            &[Fr::from(leaf_index), secret],
        ).unwrap();

        let modulus_array = biguint_to_biguint_array(MODULUS.clone(), MODULUS_LEN, BIT_SIZE);
        let nullifier_array = prime_field_to_biguint_array(nullifier, BIT_SIZE);

        let (preimage, padding_array) = gen_preimage_from_nullifier(rng, &nullifier_array);
        let (quotient, cipher) = (&preimage * &preimage).div_rem(&MODULUS);

        let quotient_array = biguint_to_biguint_array(quotient, MODULUS_LEN, BIT_SIZE);
        let cipher_field_array = gen_cipher_field_array(cipher);

        let rabin_encryption = EncryptionCircuit::<
            Fr, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>,
        >::new(
            commitment_params,
            nullifier_params,
            modulus_array,
            BIT_SIZE,
            CIPHER_BATCH,
            leaf_index,
            commitment,
            cipher_field_array,
            secret,
            quotient_array,
            padding_array,
            nullifier_array,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        rabin_encryption.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}