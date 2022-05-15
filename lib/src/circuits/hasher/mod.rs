pub mod poseidon;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_relations::r1cs::SynthesisError;

use crate::vanilla::hasher::FieldHasher;

pub trait FieldHasherGadget<F: PrimeField, FH: FieldHasher<F>> {
    type ParametersVar: AllocVar<FH::Parameters, F> + Clone;

    fn domain_type_var(width: u8) -> FpVar<F>;

    fn empty_hash_var() -> FpVar<F> {
        FpVar::Constant(FH::empty_hash())
    }

    fn hash_gadget(params: &Self::ParametersVar, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError>;

    fn hash_two_gadget(params: &Self::ParametersVar, left: FpVar<F>, right: FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        Self::hash_gadget(params, &[left, right])
    }
}