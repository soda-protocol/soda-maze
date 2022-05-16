use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;

use super::uint::GeneralUint;

pub fn polynomial_mul<F: PrimeField>(
    a: &[GeneralUint<F>],
    b: &[GeneralUint<F>],
    bit_size: usize,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    assert_eq!(a.len(), b.len());
    let order = a.len();

    let part_1 = (1..=order).into_iter().map(|i| {
        a.iter()
            .take(i)
            .zip(b.iter().take(i).rev())
            .try_fold(GeneralUint::zero(), |sum, (a, b)| {
                sum.add(&a.mul(b)?)
            })
    });
    let part_2 = (1..order).rev().into_iter().map(|i| {
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
    let mut res = part_1
        .chain(part_2)
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .map(|coeff| {
            let coeff = coeff.add(&carry)?;
            let (hi, lo) = coeff.split(bit_size)?;
            carry = hi;

            Ok(lo)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    res.push(carry);

    Ok(res)
}

pub fn polynomial_square<F: PrimeField>(
    a: &[GeneralUint<F>],
    bit_size: usize,
) -> Result<Vec<GeneralUint<F>>, SynthesisError> {
    let order = a.len();
    let part_1 = (1..=order).into_iter().map(|i| {
        let sum = a.iter()
            .take(i/2)
            .zip(a.iter().take(i).rev())
            .try_fold(GeneralUint::zero(), |sum, (a, b)| {
                sum.add(&a.mul(b)?)
            })?;
        
        let sum = sum.add(&sum)?;
        if i % 2 != 0 {
            sum.add(&a[i/2].mul(&a[i/2])?)
        } else {
            Ok(sum)
        }
    });
    let part_2 = (1..order).rev().into_iter().map(|i| {
        let sum = a.iter()
            .rev()
            .take(i)
            .rev()
            .zip(a.iter().rev().take(i/2))
            .try_fold(GeneralUint::zero(), |sum, (a, b)| {
                sum.add(&a.mul(b)?)
            })?;
        
        let sum = sum.add(&sum)?;
        if i % 2 != 0 {
            let k = (2*order-i)/2; 
            sum.add(&a[k].mul(&a[k])?)
        } else {
            Ok(sum)
        }
    });

    let mut carry = GeneralUint::zero();
    let mut res = part_1
        .chain(part_2)
        .collect::<Result<Vec<_>, SynthesisError>>()?
        .into_iter()
        .map(|elem| {
            let elem = elem.add(&carry)?;
            let (hi, lo) = elem.split(bit_size)?;
            carry = hi;

            Ok(lo)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    res.push(carry);

    Ok(res)
}

pub fn polynomial_add<F: PrimeField>(
    mut a: Vec<GeneralUint<F>>,
    mut b: Vec<GeneralUint<F>>,
    bit_size: usize,
) -> Result<(GeneralUint<F>, Vec<GeneralUint<F>>), SynthesisError> {
    if a.len() > b.len() {
        b.resize(a.len(), GeneralUint::zero());
    } else if a.len() < b.len() {
        a.resize(b.len(), GeneralUint::zero());
    }

    let mut carry = GeneralUint::zero();
    let res = a.into_iter()
        .zip(b)
        .into_iter()
        .map(|(a, b)| {
            let sum = a.add(&b)?.add(&carry)?;
            let (hi, lo) = sum.split(bit_size)?;
            carry = hi;

            Ok(lo)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    
    Ok((carry, res))
}

pub fn polynomial_force_equal<F: PrimeField>(
    a: &[GeneralUint<F>],
    b: &[GeneralUint<F>],
) -> Result<(), SynthesisError> {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .try_for_each(|(a, b)| {
            a.force_equal(b)
        })
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
    use num_bigint::BigUint;

    use super::{polynomial_mul, polynomial_add, polynomial_square};
    use super::GeneralUint;

    const BITS: usize = 124;
    const ORDER: usize = 24;

    type Uint124 = GeneralUint<Fr>;

    fn get_rand_uint124_array(rng: &mut StdRng) -> Vec<BigUint> {
        (0..ORDER)
            .into_iter()
            .map(|_| {
                let mut v = u128::rand(rng);
                v &= (1u128 << 124) - 1;

                BigUint::from(v)
            }).collect()
    }

    fn get_max_uint124_array() -> Vec<BigUint> {
        (0..ORDER)
            .into_iter()
            .map(|_| {
                BigUint::from((1u128 << 124) - 1)
            }).collect()
    }

    #[test]
    fn test_polynomial_add() {
        let rng = &mut test_rng();
        let a = get_rand_uint124_array(rng);
        let b = get_rand_uint124_array(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_constant(b.clone())
        }).collect::<Vec<_>>();
        let _ = polynomial_add(poly_a, poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_add(poly_a, poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_add(poly_a, poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_polynomial_mul() {
        let a = get_max_uint124_array();
        let b = get_max_uint124_array();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_constant(b.clone())
        }).collect::<Vec<_>>();
        let _ = polynomial_mul(&poly_a, &poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_mul(&poly_a, &poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let poly_b = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_mul(&poly_a, &poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_polynomial_square() {
        let rng = &mut test_rng();
        let a = get_max_uint124_array();
        let b = get_rand_uint124_array(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_constant(a.clone())
        }).collect::<Vec<_>>();
        let _ = polynomial_square(&poly_a, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_a = a.iter().map(|a| {
            Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_square(&poly_a, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_b = b.iter().map(|b| {
            Uint124::new_constant(b.clone())
        }).collect::<Vec<_>>();
        let _ = polynomial_square(&poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let poly_b = b.iter().map(|b| {
            Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap()
        }).collect::<Vec<_>>();
        let _ = polynomial_square(&poly_b, BITS).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}