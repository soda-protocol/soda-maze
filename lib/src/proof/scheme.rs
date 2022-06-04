use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use crate::vanilla::{hasher::FieldHasher, withdraw::*, deposit::*};
use crate::circuits::{DepositCircuit, RabinEncryption, WithdrawCircuit, FieldHasherGadget};
use super::ProofScheme;

pub struct DepositProof<F, FH, FHG, S>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
    _fhg: PhantomData<FHG>,
    _s: PhantomData<S>,
}

impl<F, FH, FHG, S> ProofScheme<
    F,
    DepositCircuit<F, FH, FHG>,
    S,
    DepositVanillaProof<F, FH>,
> for DepositProof<F, FH, FHG, S>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    fn generate_public_inputs(pub_in: &DepositPublicInputs<F>) -> Vec<F> {
        let mut inputs = Vec::new();
        inputs.push(F::from(pub_in.deposit_amount));
        inputs.push(F::from(pub_in.leaf_index));
        inputs.push(pub_in.leaf);
        inputs.push(pub_in.prev_root);
        inputs.extend_from_slice(&pub_in.update_nodes);

        if let Some(encryption) = &pub_in.encryption {
            inputs.extend_from_slice(&encryption.cipher_field_array);
        }

        inputs
    }

    fn generate_circuit(
        params: &DepositConstParams<F, FH>,
        pub_in: &DepositPublicInputs<F>,
        priv_in: &DepositPrivateInputs<F>,
    ) -> DepositCircuit<F, FH, FHG> {
        let encryption = params.encryption
            .as_ref()
            .zip(pub_in.encryption.as_ref())
            .zip(priv_in.encryption.as_ref())
            .map(|((params, pub_in), priv_in)| {
                RabinEncryption::new(
                    params.nullifier_params.clone(),
                    params.modulus_array.clone(),
                    params.bit_size,
                    params.cipher_batch,
                    pub_in.cipher_field_array.clone(),
                    priv_in.quotient_array.clone(),
                    priv_in.padding_array.clone(),
                    priv_in.nullifier_array.clone(),
                )
            });

        DepositCircuit::<F, FH, FHG>::new(
            params.leaf_params.clone(),
            params.inner_params.clone(),
            pub_in.deposit_amount,
            pub_in.leaf_index,
            pub_in.leaf,
            pub_in.prev_root,
            pub_in.update_nodes.clone(),
            priv_in.secret,
            priv_in.friend_nodes.clone(),
            encryption,
        )
    }
}

pub struct WithdrawProof<F, FH, FHG, S>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
    _fhg: PhantomData<FHG>,
    _s: PhantomData<S>,
}

impl<F, FH, FHG, S> ProofScheme<
    F,
    WithdrawCircuit<F, FH, FHG>,
    S,
    WithdrawVanillaProof<F, FH>,
> for WithdrawProof<F, FH, FHG, S>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    fn generate_public_inputs(pub_in: &WithdrawPublicInputs<F>) -> Vec<F> {
        let mut inputs = Vec::new();
        inputs.push(F::from(pub_in.withdraw_amount));
        inputs.push(pub_in.nullifier);
        inputs.push(F::from(pub_in.dst_leaf_index));
        inputs.push(pub_in.dst_leaf);
        inputs.push(pub_in.prev_root);
        inputs.extend_from_slice(&pub_in.update_nodes);

        inputs
    }

    fn generate_circuit(
        params: &WithdrawConstParams<F, FH>,
        pub_in: &WithdrawPublicInputs<F>,
        priv_in: &WithdrawPrivateInputs<F>,
    ) -> WithdrawCircuit<F, FH, FHG> {
        WithdrawCircuit::<F, FH, FHG>::new(
            params.nullifier_params.clone(),
            params.leaf_params.clone(),
            params.inner_params.clone(),
            priv_in.src_leaf_index,
            pub_in.dst_leaf_index,
            priv_in.balance,
            pub_in.withdraw_amount,
            pub_in.nullifier,
            priv_in.secret,
            pub_in.prev_root,
            pub_in.dst_leaf,
            pub_in.update_nodes.clone(),
            priv_in.src_friend_nodes.clone(),
            priv_in.dst_friend_nodes.clone(),
        )
    }
}
