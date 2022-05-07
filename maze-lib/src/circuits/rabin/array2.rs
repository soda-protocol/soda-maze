use ark_ff::PrimeField;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{SynthesisError, LinearCombination, Variable};

use super::uint2::GeneralUint;

pub fn polynomial_mul<F: PrimeField, const BIT_SIZE: u64, const ORDER: usize>(
    a: &[GeneralUint<F>],
    b: &[GeneralUint<F>],
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    assert_eq!(a.len(), ORDER);
    assert_eq!(b.len(), ORDER);

    let part_1 = (1..=ORDER).into_iter().map(|i| {
        a.iter()
            .take(i)
            .zip(b.iter().take(i).rev())
            .try_fold(GeneralUint::zero(), |sum, (a, b)| {
                sum.add(&a.mul(b)?)
            })
    });
    let part_2 = (1..ORDER).rev().into_iter().map(|i| {
        a.iter()
            .rev()
            .take(i)
            .rev()
            .zip(b.iter().rev().take(i))
            .try_fold(GeneralUint::zero(), |sum, (a, b)| {
                sum.add(&a.mul(b)?)
            })
    });

    let mut carry = GeneralUint::zero();
    let res = part_1
        .chain(part_2)
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .map(|coeff| {
            let coeff = coeff.add(&carry)?;
            let (hi, lo) = coeff.split(BIT_SIZE)?;
            carry = hi;

            Ok(lo)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    assert!(carry.is_zero());

    Ok(res)
}

pub fn polynomial_add<F: PrimeField, const BIT_SIZE: u64, const ORDER: usize>(
    a: &[GeneralUint<F>],
    b: &[GeneralUint<F>],
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    assert_eq!(a.len(), ORDER);
    assert_eq!(b.len(), ORDER);

    let mut carry = GeneralUint::zero();
    let mut res = a.iter()
        .zip(b.iter())
        .into_iter()
        .map(|(a, b)| {
            let sum = a.add(b)?.add(&carry)?;
            let (hi, lo) = sum.split(BIT_SIZE)?;
            carry = hi;

            Ok(lo)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    res.push(carry);
    
    Ok(res)
}

pub fn force_equal<F: PrimeField>(
    a: &[GeneralUint<F>],
    b: &[GeneralUint<F>],
) -> Result<(), SynthesisError> {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .try_for_each(|(a, b)| {
            a.cs().enforce_constraint(
                a.lc(),
                LinearCombination::from(Variable::One),
                b.lc(),
            )
        })
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
    use num_bigint::BigUint;

    use super::GeneralUint;

    const BITS: u64 = 124;
    const LEN: usize = 24;

    type Uint124 = GeneralUint<Fr>;

    fn get_rand_uint124_array(rng: &mut StdRng) -> Vec<BigUint> {
        (0..LEN)
            .into_iter()
            .map(|_| {
                let mut v = u128::rand(rng);
                v &= 1u128 << 124 - 1;

                BigUint::from(v)
            }).collect()
    }

    #[test]
    fn test_polynomial_mul() {
        let rng = &mut test_rng();
        let a = get_rand_uint124_array(rng);
        let b = get_rand_uint124_array(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let _ = b.iter().map(|b| {
            Uint124::new_constant(b.clone())
        }).collect::<Vec<_>>();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let _ = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap();
        }).collect::<Vec<_>>();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = a.iter().map(|a| {
            Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        }).collect::<Vec<_>>();
        let _ = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap();
        }).collect::<Vec<_>>();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}