use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;

use super::*;

#[derive(Debug, Clone)]
pub struct RabinParam {
    pub modulus: BigUint,
    pub modulus_array: Vec<BigUint>,
    pub modulus_len: usize,
    pub bit_size: usize,
    pub cypher_batch: usize,
}

impl RabinParam {
    pub fn new<F: PrimeField>(
        modulus: BigUint,
        modulus_len: usize,
        bit_size: usize,
        cypher_batch: usize,
    ) -> Self {
        assert_eq!(modulus_len % cypher_batch, 0);
        let modulus_array = biguint_to_biguint_array(modulus.clone(), modulus_len, bit_size);
        Self {
            modulus,
            modulus_array,
            modulus_len,
            bit_size,
            cypher_batch,
        }
    }

    // preimage = ... | random | ... | leaf0 | leaf1 | leaf2
    //                  lo -------------------> hi
    pub fn gen_preimage_from_leaf<F: PrimeField>(&self, leaf: F, padding: &[BigUint]) -> BigUint {
        let mut preimage_array = padding.iter().map(|p| {
            assert!(p.bits() as usize <= self.bit_size);
            p.clone()
        }).collect::<Vec<_>>();
        let leaf_array = prime_field_to_biguint_array(leaf, self.bit_size);

        preimage_array.extend(leaf_array);
        assert_eq!(preimage_array.len(), self.modulus_len);

        biguint_array_to_biguint(&preimage_array, self.bit_size)
    }

    pub fn gen_quotient_array(&self, quotient: BigUint) -> Vec<BigUint> {
        biguint_to_biguint_array(quotient, self.modulus_len, self.bit_size)
    }

    pub fn gen_cypher_array<F: PrimeField>(&self, cypher: BigUint) -> Vec<F> {
        let cypher_bits = self.cypher_batch * self.bit_size;
        assert!(cypher_bits < F::Params::MODULUS_BITS as usize);

        let cypher = biguint_to_biguint_array(
            cypher,
            self.modulus_len / self.cypher_batch,
            cypher_bits,
        );
        cypher.into_iter().map(|c| c.into()).collect()
    }
}
