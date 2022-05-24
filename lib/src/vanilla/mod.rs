pub mod merkle;
pub mod hasher;
pub mod withdraw;
pub mod deposit;
pub mod encryption;

use anyhow::Result;
use ark_ff::PrimeField;

pub trait VanillaProof<F: PrimeField> {
    type ConstParams;
    type OriginInputs: Clone;
    type PublicInputs: Clone;
    type PrivateInputs: Clone;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)>;

    fn generate_vanilla_proof(
        params: &Self::ConstParams,
        orig_in: &Self::OriginInputs,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)>;
}
