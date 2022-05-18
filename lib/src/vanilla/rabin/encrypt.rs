use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;

use super::*;

#[derive(Debug, Clone)]
pub struct RabinParam {
    pub modulus: BigUint,
    pub modulus_array: Vec<BigUint>,
    pub modulus_len: usize,
    pub bit_size: usize,
    pub cipher_batch: usize,
}

impl RabinParam {
    pub fn new<F: PrimeField>(
        modulus: BigUint,
        modulus_len: usize,
        bit_size: usize,
        cipher_batch: usize,
    ) -> Self {
        assert_eq!(modulus_len % cipher_batch, 0);
        let modulus_array = biguint_to_biguint_array(modulus.clone(), modulus_len, bit_size);
        Self {
            modulus,
            modulus_array,
            modulus_len,
            bit_size,
            cipher_batch,
        }
    }

    // preimage = ... padding ... | leaf | leaf_index
    //              lo -------------------> hi
    pub fn gen_preimage_from_leaf<F: PrimeField>(
        &self,
        leaf_index: u64,
        leaf: F,
        padding: &[BigUint],
    ) -> BigUint {
        let mut preimage = padding.iter().map(|p| {
            assert!(p.bits() as usize <= self.bit_size);
            p.clone()
        }).collect::<Vec<_>>();
        let leaf_array = prime_field_to_biguint_array(leaf, self.bit_size);

        preimage.extend(leaf_array);
        preimage.push(leaf_index.into());
        assert_eq!(preimage.len(), self.modulus_len);

        biguint_array_to_biguint(&preimage, self.bit_size)
    }

    pub fn gen_quotient_array(&self, quotient: BigUint) -> Vec<BigUint> {
        biguint_to_biguint_array(quotient, self.modulus_len, self.bit_size)
    }

    pub fn gen_cipher_array<F: PrimeField>(&self, cipher: BigUint) -> Vec<F> {
        let cipher_bits = self.cipher_batch * self.bit_size;
        assert!(cipher_bits < F::Params::MODULUS_BITS as usize);

        let cipher = biguint_to_biguint_array(
            cipher,
            self.modulus_len / self.cipher_batch,
            cipher_bits,
        );
        cipher.into_iter().map(|c| c.into()).collect()
    }
}
