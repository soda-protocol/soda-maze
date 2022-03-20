pub mod scheme;

use anyhow::{anyhow, Result};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{RngCore, CryptoRng};

use crate::vanilla::VanillaProof;

pub trait ProofScheme<F, C, S, V>
where
    F: PrimeField,
    C: ConstraintSynthesizer<F>,
    S: SNARK<F>,
    V: VanillaProof<F>,
{
    fn generate_public_inputs(pub_in: &V::PublicInputs) -> Vec<F>;

    fn generate_circuit(
        params: &V::ConstParams,
        pub_in: &V::PublicInputs,
        priv_in: &V::PrivateInputs,
    ) -> C;

    fn blank_circuit(params: &V::ConstParams) -> Result<C> {
        let (pub_in, priv_in) = V::blank_proof(params)?;

        Ok(Self::generate_circuit(params, &pub_in, &priv_in))
    }

    fn parameters_setup<R: RngCore + CryptoRng>(
        rng: &mut R,
        params: &V::ConstParams,
    ) -> Result<(S::ProvingKey, S::VerifyingKey)> {
        let circuit = Self::blank_circuit(params)?;
        let pvk = S::circuit_specific_setup(circuit, rng)
            .map_err(|e| anyhow!("parameters set up error: {}", e))?;

        Ok(pvk)
    }

    fn generate_snark_proof<R: RngCore + CryptoRng>(
        rng: &mut R,
        params: &V::ConstParams,
        pub_in: &V::PublicInputs,
        priv_in: &V::PrivateInputs,
        pk: &S::ProvingKey,
    ) -> Result<S::Proof> {
        let circuit = Self::generate_circuit(params, pub_in, priv_in);
        let proof = S::prove(pk, circuit, rng)
            .map_err(|e| anyhow!("generate snark proof error: {}", e))?;

        Ok(proof)
    }

    fn verify_snark_proof(
        pub_in: &V::PublicInputs,
        proof: &S::Proof,
        vk: &S::VerifyingKey,
    ) -> Result<bool> {
        let inputs = Self::generate_public_inputs(pub_in);
        let result = S::verify(vk, &inputs, proof)
            .map_err(|e| anyhow!("verify snark proof error: {}", e))?;

        Ok(result)
    }
}