use ark_r1cs_std::boolean::Boolean;
use ark_std::collections::HashMap;
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;

use super::uint::GeneralUint;

fn array_mul_const<F: PrimeField, const BIT: u32>(
    array: &[GeneralUint<F, BIT>],
    constant: u128,
) -> Result<Vec<GeneralUint<F, BIT>>, SynthesisError> {
    let mut res = Vec::with_capacity(array.len() + 1);
    let mut iter = array.iter();

    let (hi, lo) = iter.next().unwrap().mul_constant(constant)?;
    res.push(lo);

    let (carry, hi) = iter.try_fold((Boolean::FALSE, hi), |(carry, tmp), v| {
        let (hi, lo) = v.mul_constant(constant)?;
        let (carry, sum) = tmp.add_with_carry_and_carry_out(&lo, carry)?;
        res.push(sum);

        Ok((carry, hi))
    })?;
    let sum = hi.add_with_carry(&carry)?;
    res.push(sum);

    Ok(res)
}

fn array_mul_by_index<F: PrimeField, const BIT: u32>(
    product_map: &HashMap<(usize, usize), (GeneralUint<F, BIT>, GeneralUint<F, BIT>)>,
    len: usize,
    index: usize,
) -> Result<Vec<GeneralUint<F, BIT>>, SynthesisError> {
    assert!(index < len);

    let mut res = Vec::<GeneralUint<_, BIT>>::with_capacity(len + 1);
    let mut iter = (0..len).into_iter();

    let lookup_product = |index_0: usize, index_1| -> &(GeneralUint<F, BIT>, GeneralUint<F, BIT>) {
        let index = (index_0.min(index_1), index_0.max(index_1));
        product_map.get(&index).unwrap()
    };

    let (hi, lo) = lookup_product(iter.next().unwrap(), index);
    res.push(lo.clone());

    let (carry, hi) = iter
        .try_fold((Boolean::FALSE, hi), |(carry, tmp), i| {
            let (hi, lo) = lookup_product(i, index);
            let (carry, sum) = tmp.add_with_carry_and_carry_out(lo, carry)?;
            res.push(sum);

            Ok((carry, hi))
        })?;
    let sum = hi.add_with_carry(&carry)?;
    res.push(sum);

    Ok(res)
}

pub fn array_add_array<F: PrimeField, const BIT: u32>(
    top_array: &[GeneralUint<F, BIT>],
    bottom_array: &[GeneralUint<F, BIT>],
) -> Result<Vec<GeneralUint<F, BIT>>, SynthesisError> {
    assert!(!top_array.is_empty());
    assert_eq!(top_array.len() + 1, bottom_array.len());

    let mut res = Vec::with_capacity(bottom_array.len());
    let mut bottom_iter = bottom_array.iter();
    
    let carry = top_array
        .iter()
        .try_fold(Boolean::FALSE, |carry, top| {
            let bottom = bottom_iter.next().unwrap();
            let (carry, sum) = top.add_with_carry_and_carry_out(bottom, carry)?;
            res.push(sum);

            Ok(carry)
        })?;
    let sum = bottom_iter.next().unwrap().add_with_carry(&carry)?;
    res.push(sum);

    Ok(res)
}

pub fn array_mul_const_array<F: PrimeField, const BIT: u32>(
    array: Vec<GeneralUint<F, BIT>>,
    constants: Vec<u128>,
) -> Result<Vec<GeneralUint<F, BIT>>, SynthesisError> {
    let mut res = Vec::with_capacity(array.len() + constants.len());
    
    constants.into_iter().enumerate().try_for_each(|(i, constant)| {
        let tmp_array = array_mul_const(&array, constant)?;
        if res.is_empty() {
            res.extend_from_slice(&tmp_array);
        } else {
            let new_array = array_add_array(&res[i..], &tmp_array)?;
            res.truncate(i);
            res.extend(new_array);
        }

        Ok(())
    })?;

    Ok(res)
}

pub fn array_square<F: PrimeField, const BIT: u32>(
    array: Vec<GeneralUint<F, BIT>>,
) -> Result<Vec<GeneralUint<F, BIT>>, SynthesisError> {
    let mut product_map = HashMap::new();
    array.iter().enumerate().try_for_each(|(i, elem)| {
        array.iter().skip(i).enumerate().try_for_each(|(j, other)| {
            let product = elem.mul(other)?;
            product_map.insert((i, i + j), product);

            Ok(())
        })
    })?;

    let len = array.len();
    let mut res = Vec::with_capacity(len * 2);
    (0..len).into_iter().try_for_each(|i| {
        let tmp_array = array_mul_by_index(&product_map, len, i)?;
        if res.is_empty() {
            res.extend(tmp_array);
        } else {
            let new_array = array_add_array(&res[i as usize..], &tmp_array)?;
            res.truncate(i as usize);
            res.extend(new_array);
        }

        Ok(())
    })?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;

    use super::{GeneralUint, array_square, array_mul_const_array};

    const BITS: u32 = 126;
    const LEN: u32 = 24;

    type Uint126 = GeneralUint<Fr, BITS>;

    fn get_rand_uint126(rng: &mut StdRng) -> u128 {
        let mut v = u128::rand(rng);
        v &= 0x3FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;

        v
    }

    #[test]
    fn test_array_square() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let array = (0..LEN).into_iter().map(|_| {
            Uint126::new_witness(cs.clone(), || Ok(get_rand_uint126(rng)), BITS).unwrap()
        }).collect::<Vec<_>>();

        let _ = array_square::<_, BITS>(array).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
        println!("{}", cs.num_witness_variables());
    }

    #[test]
    fn test_array_mul_const() {
        let rng = &mut test_rng();
        let constant_array = (0..LEN).into_iter().map(|_| {
            get_rand_uint126(rng)
        }).collect::<Vec<_>>();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let array = (0..LEN).into_iter().map(|_| {
            Uint126::new_witness(cs.clone(), || Ok(get_rand_uint126(rng)), BITS).unwrap()
        }).collect::<Vec<_>>();

        let _ = array_mul_const_array::<_, BITS>(array, constant_array).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
        println!("{}", cs.num_witness_variables());
    }
}