use ark_std::rc::Rc;
use anyhow::{anyhow, Result};
use ark_ff::{PrimeField, BigInteger, FpParameters};
use ark_ec::{models::{TEModelParameters, twisted_edwards_extended::GroupProjective}, ProjectiveCurve};

use super::hasher::FieldHasher;

#[derive(Debug)]
pub struct JubjubConstParams<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    pub nullifier_params: Rc<FH::Parameters>,
    pub pubkey: GroupProjective<P>,
}

#[derive(Debug)]
pub struct JubjubOriginInputs<P: TEModelParameters> {
    pub nonce: P::ScalarField,
}

#[derive(Debug)]
pub struct JubjubPublicInputs<P: TEModelParameters> {
    pub commitment: (GroupProjective<P>, GroupProjective<P>),
}

#[derive(Debug)]
pub struct JubjubPrivateInputs {
    pub nonce_bits: Vec<bool>,
}

pub fn generate_vanilla_proof<P, FH>(
    params: &JubjubConstParams<P, FH>,
    orig_in: &JubjubOriginInputs<P>,
    leaf_index: u64,
    secret: P::BaseField,
) -> Result<(JubjubPublicInputs<P>, JubjubPrivateInputs)>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    let scalar_bits = <<P::ScalarField as PrimeField>::Params as FpParameters>::CAPACITY as usize;

    // convert nonce to nonce bits
    let nonce: <P::ScalarField as PrimeField>::BigInt = orig_in.nonce.into();
    let mut nonce_bits = nonce.to_bits_le();
    nonce_bits.truncate(scalar_bits);
    let nonce: <P::ScalarField as PrimeField>::BigInt = <<P::ScalarField as PrimeField>::BigInt as BigInteger>::from_bits_le(&nonce_bits);

    let nullifier = FH::hash(
        &params.nullifier_params,
        &[P::BaseField::from(leaf_index), secret],
    ).map_err(|e| anyhow!("hash error: {}", e))?;

    // truncate nullifier to scalar field
    let nullifier: <P::BaseField as PrimeField>::BigInt = nullifier.into();
    let mut nullifier_bits = nullifier.to_bits_le();
    nullifier_bits.truncate(scalar_bits);
    let nullifier: <P::ScalarField as PrimeField>::BigInt = <<P::ScalarField as PrimeField>::BigInt as BigInteger>::from_bits_le(&nullifier_bits);

    // encrypt step 1: nonce * G
    let g = GroupProjective::prime_subgroup_generator();
    let commitment_0 = g.mul(nonce);
    
    // encrypt step 2: nullifier * G + nonce * P
    let commitment_1 = g.mul(nullifier) + params.pubkey.mul(nonce);

    let pub_in = JubjubPublicInputs {
        commitment: (commitment_0, commitment_1),
    };
    let priv_in = JubjubPrivateInputs { nonce_bits };

    Ok((pub_in, priv_in))
}