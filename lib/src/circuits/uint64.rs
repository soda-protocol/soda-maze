use ark_r1cs_std::{uint64::UInt64, boolean::Boolean, fields::fp::FpVar, alloc::AllocVar, ToBitsGadget};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};
use ark_ff::PrimeField;

pub struct Uint64<F: PrimeField> {
    variable: FpVar<F>,
    uint: UInt64<F>,
}

impl<F: PrimeField> Uint64<F> {
    pub fn new_witness(cs: ConstraintSystemRef<F>, f: impl FnOnce() -> Result<u64, SynthesisError>) -> Result<Self, SynthesisError> {
        let uint = UInt64::new_witness(cs.clone(), f)?;
        let variable = Boolean::le_bits_to_fp_var(&uint.to_bits_le())?;

        Ok(Self {
            variable,
            uint,
        })
    }

    #[allow(dead_code)]
    pub fn new_constant(cs: ConstraintSystemRef<F>, value: u64) -> Result<Self, SynthesisError> {
        let variable = FpVar::new_constant(cs.clone(), F::from(value))?;
        let uint = UInt64::new_constant(cs.clone(), value)?;

        Ok(Self {
            variable,
            uint,
        })
    }

    pub fn fp_var(&self) -> &FpVar<F> {
        &self.variable
    }
}

impl<F: PrimeField> ToBitsGadget<F> for Uint64<F> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self.uint.to_bits_le())
    }
}