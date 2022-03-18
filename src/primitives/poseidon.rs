use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_crypto_primitives::Error;
use arkworks_utils::poseidon::{PoseidonParameters, PoseidonError};
use arkworks_gadgets::poseidon::CRH as PoseidonCRH;

use super::hasher::FieldHasher;

pub struct PoseidonHasher<F>(PhantomData<F>);

impl<F: PrimeField> FieldHasher<F> for PoseidonHasher<F> {
    type Parameters = PoseidonParameters<F>;

    fn empty_hash() -> F {
        F::zero()
    }

    fn hash(params: &Self::Parameters, inputs: &[F]) -> Result<F, Error> {
        assert!(
            inputs.len() < params.width.into(),
            "incorrect input length {:?} for width {:?}",
            inputs.len(),
            params.width,
        );

        let mut buffer = Vec::with_capacity(params.width as usize);
        buffer.push(F::zero());
        buffer.extend_from_slice(inputs);
        buffer.resize(params.width as usize, F::zero());

		let result = PoseidonCRH::permute(params, buffer)?
            .get(0)
            .cloned()
            .ok_or(PoseidonError::InvalidInputs)?;

        Ok(result)
    }
}