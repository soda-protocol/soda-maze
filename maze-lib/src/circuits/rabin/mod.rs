pub mod uint126;

use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;

use uint126::Uint126;

fn array_mul_const<F: PrimeField>(
    array: &[Uint126<F>],
    constant: u128,
) -> Result<Vec<Uint126<F>>, SynthesisError> {
    assert!(!array.is_empty());

    let mut res = Vec::with_capacity(array.len() + 1);
    let mut iter = array.iter();

    let (hi, lo) = iter.next().unwrap().mul_constant(constant)?;
    res.push(lo);
    let mut tmp = hi;

    if let Some(v) = iter.next() {
        let (hi, lo) = v.mul_constant(constant)?;
        let (c, sum) = tmp.add_no_carry(&lo)?;
        res.push(sum);
        tmp = hi;
        let mut carry = c;

        iter.try_for_each(|val| {
            let (hi, lo) = val.mul_constant(constant)?;
            let (c, sum) = tmp.add_with_carry(&lo, &carry)?;
            res.push(sum);
            tmp = hi;
            carry = c;

            Ok(())
        })?;
        tmp = tmp.add_carry(&carry)?;
    }

    res.push(tmp);

    Ok(res)
}

fn array_add_array<F: PrimeField>(
    top_array: &[Uint126<F>],
    bottom_array: Vec<Uint126<F>>,
) -> Result<Vec<Uint126<F>>, SynthesisError> {
    assert!(!top_array.is_empty());
    assert_eq!(top_array.len() + 1, bottom_array.len());

    let mut res = Vec::with_capacity(bottom_array);
    let mut top_iter = top_array.iter();
    let mut bottom_iter = bottom_array.into_iter();
    
    let (c, sum) = top_iter.next().unwrap().add_no_carry(&bottom_iter.next().unwrap())?;
    res.push(sum);
    let mut carry = c;

    top_iter.try_for_each(|top| {
        let bottom = bottom_iter.next().unwrap();
        let (c, sum) = top.add_with_carry(&bottom, &carry)?;
        res.push(sum);
        carry = c;

        Ok(())
    })?;

    let sum = bottom_iter.next().unwrap().add_carry(&carry)?;
    res.push(sum);

    Ok(res)
}

pub fn array_mul_const_array<F: PrimeField>(
    array: Vec<Uint126<F>>,
    constants: Vec<u128>,
) -> Result<Vec<Uint126<F>>, SynthesisError> {
    assert!(!constants.is_empty());
    let mut res = Vec::with_capacity(array.len() + constants.len());
    let mut constants_iter = constants.into_iter();

    constants_iter.enumerate().try_for_each(|(i, constant)| {
        let tmp_array = array_mul_const(&array, constant)?;
        if res.is_empty() {
            res.extend(tmp_array);
        } else {
            let new_array = array_add_array(&res[i..], tmp_array)?;
            res.truncate(i);
            res.extend(new_array);
        }

        Ok(())
    })?;

    Ok(res)
}