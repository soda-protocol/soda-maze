pub mod merkle;
pub mod hasher;
pub mod withdraw;
pub mod deposit;
pub mod commit;

use anyhow::Result;
use ark_ff::PrimeField;

pub trait VanillaProof<F: PrimeField> {
    type ConstParams;
    type OriginInputs;
    type PublicInputs;
    type PrivateInputs;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)>;

    fn generate_vanilla_proof(
        params: &Self::ConstParams,
        orig_in: &Self::OriginInputs,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)>;
}
