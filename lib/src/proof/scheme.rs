use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use crate::vanilla::{hasher::FieldHasher, proof::*};
use crate::circuits::{WithdrawCircuit, FieldHasherGadget, RabinEncryption};

use super::ProofScheme;

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
        inputs.push(pub_in.mint.to_field_element());
        inputs.push(F::from(pub_in.withdraw_amount));
        inputs.push(pub_in.nullifier);
        
        if let Some(cipher) = &pub_in.cipher {
            inputs.extend_from_slice(cipher);
        }

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
        let rabin_encrytion = if let Some(param) = &params.rabin_param {
            Some(RabinEncryption::new(
                param.modulus_array.clone(),
                priv_in.quotient.clone().unwrap(),
                priv_in.random_padding.clone().unwrap(),
                pub_in.cipher.clone().unwrap(),
                priv_in.old_leaf,
                priv_in.old_leaf_index,
                params.height,
                param.bit_size,
                param.cipher_batch,
            ))
        } else {
            None
        };

        WithdrawCircuit::<F, FH, FHG>::new(
            pub_in.mint,
            pub_in.withdraw_amount,
            priv_in.deposit_amount,
            pub_in.nullifier,
            priv_in.secret,
            pub_in.new_leaf_index,
            pub_in.new_leaf,
            pub_in.old_root,
            priv_in.friend_nodes_1.clone(),
            priv_in.friend_nodes_2.clone(),
            pub_in.update_nodes.clone(),
            params.secret_params.clone(),
            params.nullifier_params.clone(),
            params.leaf_params.clone(),
            params.inner_params.clone(),
            rabin_encrytion,
        )
    }
}
