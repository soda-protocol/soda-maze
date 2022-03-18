use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_relations::r1cs::SynthesisError;

use crate::primitives::hasher::FieldHasher;

pub trait FieldHasherGadget<F: PrimeField, H: FieldHasher<F>> {
    type ParametersVar: AllocVar<H::Parameters, F> + Clone;

    fn empty_hash_var() -> FpVar<F> {
        FpVar::Constant(H::empty_hash())
    }

    fn hash_gadget(params: &Self::ParametersVar, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError>;

    fn hash_two_gadget(params: &Self::ParametersVar, left: FpVar<F>, right: FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        Self::hash_gadget(params, &[left, right])
    }
}
