use anyhow::{anyhow, Result};
use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;
use num_integer::Integer;

use super::biguint::*;
use crate::vanilla::hasher::FieldHasher;

pub struct EncryptionConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub nullifier_params: FH::Parameters,
    pub modulus_array: Vec<BigUint>,
    pub modulus_len: usize,
    pub bit_size: usize,
    pub cipher_batch: usize,
}

#[derive(Clone)]
pub struct EncryptionOriginInputs {
    pub padding_array: Vec<BigUint>,
}

#[derive(Clone)]
pub struct EncryptionPublicInputs<F: PrimeField> {
    pub cipher_field_array: Vec<F>,
}

#[derive(Clone)]
pub struct EncryptionPrivateInputs {
    pub quotient_array: Vec<BigUint>,
    pub padding_array: Vec<BigUint>,
    pub nullifier_array: Vec<BigUint>,
}

pub fn gen_origin_inputs<F: PrimeField, FH: FieldHasher<F>>(
    params: &EncryptionConstParams<F, FH>,
) -> EncryptionOriginInputs {
    let mut leaf_len = F::Params::MODULUS_BITS as usize / params.bit_size;
    if F::Params::MODULUS_BITS as usize % params.bit_size != 0 {
        leaf_len += 1;
    }
    let padding_array = vec![BigUint::from(0u64); params.modulus_len - leaf_len];
    
    EncryptionOriginInputs { padding_array }
}

pub fn generate_vanilla_proof<F: PrimeField, FH: FieldHasher<F>>(
    params: &EncryptionConstParams<F, FH>,
    orig_in: &EncryptionOriginInputs,
    leaf_index: u64,
    secret: F,
) -> Result<(EncryptionPublicInputs<F>, EncryptionPrivateInputs)> {
    assert_eq!(params.modulus_array.len(), params.modulus_len);
    assert_eq!(params.modulus_len % params.cipher_batch, 0);

    let modulus = biguint_array_to_biguint(&params.modulus_array, params.bit_size);
    
    let nullifier = FH::hash(
        &params.nullifier_params,
        &[F::from(leaf_index), secret],
    ).map_err(|e| anyhow!("hash error: {}", e))?;

    // gen preimage from nullifier
    let mut preimage = orig_in.padding_array.iter().map(|p| {
        assert!(p.bits() as usize <= params.bit_size);
        p.clone()
    }).collect::<Vec<_>>();
    let nullifier_array = prime_field_to_biguint_array(nullifier, params.bit_size);
    preimage.extend_from_slice(&nullifier_array);
    assert_eq!(preimage.len(), params.modulus_len);

    // calculate quotient and cipher
    let preimage_biguint = biguint_array_to_biguint(&preimage, params.bit_size);
    assert!(&preimage_biguint < &modulus);
    let (quotient, cipher) = (&preimage_biguint * &preimage_biguint).div_rem(&modulus);
    
    // gen quotient array
    let quotient_array = biguint_to_biguint_array(quotient, params.modulus_len, params.bit_size);

    // gen cipher field array
    let cipher_field_array: Vec<F> = {
        let cipher_bits = params.cipher_batch * params.bit_size;
        assert!(cipher_bits < F::Params::MODULUS_BITS as usize);
        let cipher_array = biguint_to_biguint_array(
            cipher,
            params.modulus_len / params.cipher_batch,
            cipher_bits,
        );
        cipher_array.into_iter().map(|c| c.into()).collect()
    };

    let pub_in = EncryptionPublicInputs {
        cipher_field_array,
    };
    let priv_in = EncryptionPrivateInputs {
        quotient_array,
        padding_array: orig_in.padding_array.clone(),
        nullifier_array,
    };

    Ok((pub_in, priv_in))
}
