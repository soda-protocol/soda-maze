use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use crate::vanilla::{hasher::FieldHasher, proof::*};
use crate::circuits::{DepositCircuit, WithdrawCircuit, FieldHasherGadget};

use super::ProofScheme;

pub struct DepositProof<F, FH, FHG, S, const HEIGHT: u8>
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

impl<F, FH, FHG, S, const HEIGHT: u8> ProofScheme<
    F,
    DepositCircuit<F, FH, FHG>,
    S,
    DepositVanillaProof<F, FH, HEIGHT>,
> for DepositProof<F, FH, FHG, S, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    fn generate_public_inputs(pub_in: &DepositPublicInputs<F>) -> Vec<F> {
        let mut inputs = Vec::new();
        inputs.push(pub_in.mint.to_field_element());
        inputs.push(F::from(pub_in.amount));
        inputs.push(F::from(pub_in.leaf_index));
        inputs.push(pub_in.new_leaf);
        inputs.extend_from_slice(&pub_in.update_nodes);
        inputs.push(pub_in.old_root);

        inputs
    }

    fn generate_circuit(
        params: &ConstParams<F, FH>,
        pub_in: &DepositPublicInputs<F>,
        priv_in: &DepositPrivateInputs<F>,
    ) -> DepositCircuit<F, FH, FHG> {
        DepositCircuit::<F, FH, FHG>::new(
            pub_in.mint,
            pub_in.amount,
            priv_in.secret,
            params.leaf_params.clone(),
            pub_in.leaf_index,
            pub_in.old_root,
            pub_in.new_leaf,
            priv_in.friend_nodes.clone(),
            pub_in.update_nodes.clone(),
            params.inner_params.clone(),
        )
    }
}

pub struct WithdrawProof<F, FH, FHG, S, const HEIGHT: u8>
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

impl<F, FH, FHG, S, const HEIGHT: u8> ProofScheme<
    F,
    WithdrawCircuit<F, FH, FHG>,
    S,
    WithdrawVanillaProof<F, FH, HEIGHT>,
> for WithdrawProof<F, FH, FHG, S, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
    S: SNARK<F>,
{
    fn generate_public_inputs(pub_in: &WithdrawPublicInputs<F>) -> Vec<F> {
        let mut inputs = Vec::new();
        inputs.push(pub_in.mint.to_field_element());
        inputs.push(F::from(pub_in.withdraw_amount));
        inputs.push(pub_in.nullifier);
        inputs.push(pub_in.root);

        inputs
    }

    fn generate_circuit(
        params: &ConstParams<F, FH>,
        pub_in: &WithdrawPublicInputs<F>,
        priv_in: &WithdrawPrivateInputs<F>,
    ) -> WithdrawCircuit<F, FH, FHG> {
        WithdrawCircuit::<F, FH, FHG>::new(
            pub_in.mint,
            pub_in.withdraw_amount,
            priv_in.deposit_amount,
            priv_in.secret,
            pub_in.nullifier,
            params.leaf_params.clone(),
            pub_in.root,
            priv_in.friend_nodes.clone(),
            params.inner_params.clone(),
        )
    }
}
