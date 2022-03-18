use ark_std::cmp::Ordering;
use ark_r1cs_std::{uint64::UInt64, boolean::Boolean, fields::fp::FpVar, alloc::AllocVar, eq::EqGadget, R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
use ark_ff::PrimeField;

pub struct Uint64<F: PrimeField> {
    variable: FpVar<F>,
    uint64: UInt64<F>,
}

impl<F: PrimeField> Uint64<F> {
    pub fn new_input(cs: ConstraintSystemRef<F>, f: impl FnOnce() -> Result<u64, SynthesisError>) -> Result<Self, SynthesisError> {
        let uint64 = UInt64::new_witness(cs.clone(), f)?;
        let var = Boolean::le_bits_to_fp_var(&uint64.to_bits_le())?;
        let variable = FpVar::new_input(cs.clone(), || var.value())?;
        var.enforce_equal(&variable)?;

        Ok(Self {
            variable,
            uint64,
        })
    }

    pub fn new_witness(cs: ConstraintSystemRef<F>, f: impl FnOnce() -> Result<u64, SynthesisError>) -> Result<Self, SynthesisError> {
        let uint64 = UInt64::new_witness(cs.clone(), f)?;
        let variable = Boolean::le_bits_to_fp_var(&uint64.to_bits_le())?;

        Ok(Self {
            variable,
            uint64,
        })
    }

    #[allow(dead_code)]
    pub fn new_constant(cs: ConstraintSystemRef<F>, value: u64) -> Result<Self, SynthesisError> {
        let variable = FpVar::new_constant(cs.clone(), F::from(value))?;
        let uint64 = UInt64::new_constant(cs.clone(), value)?;

        Ok(Self {
            variable,
            uint64,
        })
    }

    pub fn fp_var(&self) -> &FpVar<F> {
        &self.variable
    }

    pub fn is_less_and_equal_than(&self, other: &Self) -> Result<(), SynthesisError> {
        // uint64 is always less than (p-1)/2
        self.variable.enforce_cmp_unchecked(
            &other.variable,
            Ordering::Less,
            true,
        )
    }
}

impl<F: PrimeField> ToBitsGadget<F> for Uint64<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self.uint64.to_bits_le())
    }
}