pub mod poseidon;

use ark_crypto_primitives::Error;
use ark_ff::PrimeField;

pub trait FieldHasher<F: PrimeField> {
	type Parameters: Clone + Default;

    /// The domain tag is the first element of a Poseidon permutation.
    /// This extra element is necessary for 128-bit security.
	fn domain_type(width: u8) -> F;

    fn empty_hash() -> F;

	fn hash(params: &Self::Parameters, inputs: &[F]) -> Result<F, Error>;
	
	fn hash_two(params: &Self::Parameters, left: F, right: F) -> Result<F, Error> {
		Self::hash(params, &[left, right])
	}
}