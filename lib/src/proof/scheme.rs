use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use crate::vanilla::{hasher::FieldHasher, withdraw::*, encryption::*};
use crate::circuits::{WithdrawCircuit, FieldHasherGadget, EncryptionCircuit};
use super::ProofScheme;

pub struct EncryptionProof<F, FH, FHG, S>
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
    EncryptionCircuit<F, FH, FHG>,
    S,
    EncryptionVanillaProof<F, FH>,
> for EncryptionProof<F, FH, FHG, S>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    fn generate_public_inputs(pub_in: &EncryptionPublicInputs<F>) -> Vec<F> {
        let mut inputs = Vec::new();
        inputs.push(F::from(pub_in.leaf_index));
        inputs.push(pub_in.commitment);
        inputs.extend_from_slice(&pub_in.cipher_field_array);

        inputs
    }

    fn generate_circuit(
        params: &EncryptionConstParams<F, FH>,
        pub_in: &EncryptionPublicInputs<F>,
        priv_in: &EncryptionPrivateInputs<F>,
    ) -> EncryptionCircuit<F, FH, FHG> {
        EncryptionCircuit::<F, FH, FHG>::new(
            params.commitment_params.clone(),
            params.nullifier_params.clone(),
            params.modulus_array.clone(),
            params.bit_size,
            params.cipher_batch,
            pub_in.leaf_index,
            pub_in.commitment,
            pub_in.cipher_field_array.clone(),
            priv_in.secret,
            priv_in.quotient_array.clone(),
            priv_in.padding_array.clone(),
            priv_in.nullifier_array.clone(),
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
        inputs.push(pub_in.old_root);
        inputs.push(F::from(pub_in.new_leaf_index));
        inputs.push(pub_in.new_leaf);
        inputs.extend_from_slice(&pub_in.update_nodes);

        inputs
    }

    fn generate_circuit(
        params: &WithdrawConstParams<F, FH>,
        pub_in: &WithdrawPublicInputs<F>,
        priv_in: &WithdrawPrivateInputs<F>,
    ) -> WithdrawCircuit<F, FH, FHG> {
        WithdrawCircuit::<F, FH, FHG>::new(
            params.commitment_params.clone(),
            params.nullifier_params.clone(),
            params.leaf_params.clone(),
            params.inner_params.clone(),
            pub_in.withdraw_amount,
            pub_in.nullifier,
            pub_in.new_leaf_index,
            pub_in.new_leaf,
            pub_in.old_root,
            pub_in.update_nodes.clone(),
            priv_in.deposit_amount,
            priv_in.secret_1,
            priv_in.secret_2,
            priv_in.friend_nodes_1.clone(),
            priv_in.friend_nodes_2.clone(),
        )
    }
}
