use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::SynthesisError;
use arkworks_gadgets::poseidon::constraints::{PoseidonParametersVar, CRHGadget as PoseidonCRHGadget};

use crate::vanilla::hasher::{poseidon::PoseidonHasher, FieldHasher};
use super::FieldHasherGadget;

pub struct PoseidonHasherGadget<F>(PhantomData<F>);

impl<F: PrimeField> FieldHasherGadget<F, PoseidonHasher<F>> for PoseidonHasherGadget<F> {
    type ParametersVar = PoseidonParametersVar<F>;

    fn domain_type_var(width: u8) -> FpVar<F> {
        FpVar::Constant(PoseidonHasher::domain_type(width))
    }

    fn hash_gadget(params: &Self::ParametersVar, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        assert!(
            inputs.len() < params.width.into(),
            "incorrect input length {:?} for width {:?}",
            inputs.len(),
            params.width,
        );

        let mut buffer = Vec::with_capacity(params.width as usize);
        buffer.push(Self::domain_type_var(params.width));
        buffer.extend_from_slice(inputs);
        buffer.resize(params.width as usize, FpVar::zero());

        PoseidonCRHGadget::permute(params, buffer)
            .map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
    }
}
