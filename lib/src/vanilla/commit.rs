use ark_std::rc::Rc;
use anyhow::{anyhow, Result};
use ark_ff::{PrimeField, BigInteger, FpParameters};
use ark_ec::{models::{TEModelParameters, twisted_edwards_extended::{GroupProjective, GroupAffine}}, ProjectiveCurve};

use super::hasher::FieldHasher;

#[derive(Debug)]
pub struct CommitConstParams<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    pub nullifier_params: Rc<FH::Parameters>,
    pub pubkey: GroupAffine<P>,
}

#[derive(Debug)]
pub struct CommitOriginInputs<P: TEModelParameters> {
    pub nonce: P::ScalarField,
}

#[derive(Debug)]
pub struct CommitPublicInputs<P: TEModelParameters> {
    pub commitment: (GroupAffine<P>, GroupAffine<P>),
}

#[derive(Debug)]
pub struct CommitPrivateInputs {
    pub nonce_bits: Vec<bool>,
}

pub fn generate_vanilla_proof<P, FH>(
    params: &CommitConstParams<P, FH>,
    orig_in: &CommitOriginInputs<P>,
    leaf_index: u64,
    secret: P::BaseField,
) -> Result<(CommitPublicInputs<P>, CommitPrivateInputs)>
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
    let pubkey: GroupProjective<_> = params.pubkey.into();
    let commitment_1 = g.mul(nullifier) + pubkey.mul(nonce);

    let pub_in = CommitPublicInputs {
        commitment: (commitment_0.into(), commitment_1.into()),
    };
    let priv_in = CommitPrivateInputs { nonce_bits };

    Ok((pub_in, priv_in))
}