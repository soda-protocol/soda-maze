use std::borrow::Borrow;

use ark_r1cs_std::{uint64::UInt64, boolean::Boolean, fields::fp::FpVar, alloc::{AllocVar, AllocationMode}};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
use ark_ff::{PrimeField};

pub struct Uint64<F: PrimeField> {
    bits: UInt64<F>,
    var: Option<FpVar<F>>,
}

impl<F: PrimeField> Uint64<F> {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<u64, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let a = UInt64::new_witness(cs, f)?;
    }
} 

pub fn uint64_to_variable<F: PrimeField>(var: &UInt64<F>) -> Result<FpVar<F>, SynthesisError> {
    let a = var.to_bits_le();
    let var = Boolean::le_bits_to_fp_var(&a)?;

    Ok(var)
}

pub fn is_less_and_equal_than<F: PrimeField>(var1: &FpVar<F>, var2: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
    var1
}