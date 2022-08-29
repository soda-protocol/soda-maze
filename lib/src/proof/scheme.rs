use ark_crypto_primitives::snark::SNARK;
use ark_ec::{TEModelParameters, twisted_edwards_extended::GroupAffine};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use crate::vanilla::{hasher::FieldHasher, withdraw::*, deposit::*};
use crate::circuits::{DepositCircuit, JubjubEncrypt, WithdrawCircuit, FieldHasherGadget};
use super::ProofScheme;

pub struct DepositProof<P, FH, FHG, S>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    S: SNARK<P::BaseField>,
    P::BaseField: PrimeField,
{
    _p: PhantomData<P>,
    _fh: PhantomData<FH>,
    _fhg: PhantomData<FHG>,
    _s: PhantomData<S>,
}

impl<P, FH, FHG, S> ProofScheme<
    P::BaseField,
    DepositCircuit<P, FH, FHG>,
    S,
    DepositVanillaProof<P, FH>,
> for DepositProof<P, FH, FHG, S>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    S: SNARK<P::BaseField>,
    P::BaseField: PrimeField,
{
    fn generate_public_inputs(pub_in: &DepositPublicInputs<P>) -> Vec<P::BaseField> {
        let mut inputs = Vec::new();
        inputs.push(P::BaseField::from(pub_in.deposit_amount));
        inputs.push(P::BaseField::from(pub_in.leaf_index));
        inputs.push(pub_in.leaf);
        inputs.push(pub_in.prev_root);
        inputs.extend_from_slice(&pub_in.update_nodes);

        if let Some(jubjub) = &pub_in.jubjub {
            let commitment_0: GroupAffine<P> = jubjub.commitment.0.into();
            let commitment_1: GroupAffine<P> = jubjub.commitment.1.into();
            inputs.push(commitment_0.x);
            inputs.push(commitment_0.y);
            inputs.push(commitment_1.x);
            inputs.push(commitment_1.y);
        }

        inputs
    }

    fn generate_circuit(
        params: &DepositConstParams<P, FH>,
        pub_in: &DepositPublicInputs<P>,
        priv_in: &DepositPrivateInputs<P>,
    ) -> DepositCircuit<P, FH, FHG> {
        let jubjub = params.jubjub
            .as_ref()
            .zip(pub_in.jubjub.as_ref())
            .zip(priv_in.jubjub.as_ref())
            .map(|((params, pub_in), priv_in)| {
                JubjubEncrypt::new(
                    params.nullifier_params.clone(),
                    params.pubkey,
                    priv_in.nonce_bits.clone(),
                    pub_in.commitment.clone(),
                )
            });

        DepositCircuit::<P, FH, FHG>::new(
            params.leaf_params.clone(),
            params.inner_params.clone(),
            pub_in.deposit_amount,
            pub_in.leaf_index,
            pub_in.leaf,
            pub_in.prev_root,
            pub_in.update_nodes.clone(),
            priv_in.secret,
            priv_in.neighbor_nodes.clone(),
            jubjub,
        )
    }
}

pub struct WithdrawProof<P, FH, FHG, S>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    S: SNARK<P::BaseField>,
    P::BaseField: PrimeField,
{
    _p: PhantomData<P>,
    _fh: PhantomData<FH>,
    _fhg: PhantomData<FHG>,
    _s: PhantomData<S>,
}

impl<P, FH, FHG, S> ProofScheme<
    P::BaseField,
    WithdrawCircuit<P, FH, FHG>,
    S,
    WithdrawVanillaProof<P, FH>,
> for WithdrawProof<P, FH, FHG, S>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    S: SNARK<P::BaseField>,
    P::BaseField: PrimeField,
{
    fn generate_public_inputs(pub_in: &WithdrawPublicInputs<P>) -> Vec<P::BaseField> {
        let mut inputs = Vec::new();
        inputs.push(P::BaseField::from(pub_in.withdraw_amount));
        inputs.push(pub_in.receiver);
        inputs.push(pub_in.nullifier);
        inputs.push(P::BaseField::from(pub_in.dst_leaf_index));
        inputs.push(pub_in.dst_leaf);
        inputs.push(pub_in.prev_root);
        inputs.extend_from_slice(&pub_in.update_nodes);

        if let Some(jubjub) = &pub_in.jubjub {
            let commitment_0: GroupAffine<P> = jubjub.commitment.0.into();
            let commitment_1: GroupAffine<P> = jubjub.commitment.1.into();
            inputs.push(commitment_0.x);
            inputs.push(commitment_0.y);
            inputs.push(commitment_1.x);
            inputs.push(commitment_1.y);
        }

        inputs
    }

    fn generate_circuit(
        params: &WithdrawConstParams<P, FH>,
        pub_in: &WithdrawPublicInputs<P>,
        priv_in: &WithdrawPrivateInputs<P>,
    ) -> WithdrawCircuit<P, FH, FHG> {
        let jubjub = params.jubjub
            .as_ref()
            .zip(pub_in.jubjub.as_ref())
            .zip(priv_in.jubjub.as_ref())
            .map(|((params, pub_in), priv_in)| {
                JubjubEncrypt::new(
                    params.nullifier_params.clone(),
                    params.pubkey,
                    priv_in.nonce_bits.clone(),
                    pub_in.commitment.clone(),
                )
            });

        WithdrawCircuit::<P, FH, FHG>::new(
            params.nullifier_params.clone(),
            params.leaf_params.clone(),
            params.inner_params.clone(),
            priv_in.src_leaf_index,
            pub_in.dst_leaf_index,
            priv_in.balance,
            pub_in.withdraw_amount,
            pub_in.receiver,
            pub_in.nullifier,
            pub_in.prev_root,
            pub_in.dst_leaf,
            pub_in.update_nodes.clone(),
            priv_in.secret,
            priv_in.src_neighbor_nodes.clone(),
            priv_in.dst_neighbor_nodes.clone(),
            jubjub,
        )
    }
}
