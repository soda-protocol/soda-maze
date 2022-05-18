pub mod poseidon;
pub mod mimc;

use ark_crypto_primitives::Error;
use ark_ff::PrimeField;

pub trait FieldHasher<F: PrimeField> {
	type Parameters: Clone + Default;

    fn empty_hash() -> F;

	fn hash(params: &Self::Parameters, inputs: &[F]) -> Result<F, Error>;
	
	fn hash_two(params: &Self::Parameters, left: F, right: F) -> Result<F, Error> {
		Self::hash(params, &[left, right])
	}
}