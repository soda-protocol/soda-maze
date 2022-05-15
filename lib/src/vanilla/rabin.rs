use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;
use num_integer::Integer;

#[derive(Debug, Clone)]
pub struct RabinParam {
    pub modulus: BigUint,
    pub modulus_array: Vec<BigUint>,
    pub modulus_len: usize,
    pub bit_size: u64,
    pub cypher_batch: usize,
}

impl RabinParam {
    pub fn new<F: PrimeField>(
        modulus: BigUint,
        modulus_len: usize,
        bit_size: u64,
        cypher_batch: usize,
    ) -> Self {
        let base = BigUint::from(1u64) << bit_size;
        let mut rest = modulus.clone();
        let modulus_array = (0..modulus_len).into_iter().map(|_| {
            let (hi, lo) = rest.div_rem(&base);
            rest = hi;

            lo
        }).collect::<Vec<_>>();

        Self {
            modulus,
            modulus_array,
            modulus_len,
            bit_size,
            cypher_batch,
        }
    }

    pub fn gen_preimage<F: PrimeField>(
        &self,
        leaf: F,
    ) -> BigUint {
        let leaf_uint: BigUint = leaf.into();
        let modulus_bits = F::Params::MODULUS_BITS as usize;
        let mut batch_size = modulus_bits / (self.bit_size as usize);
        if modulus_bits % (self.bit_size as usize) != 0 {
            batch_size += 1;
        }
    
        let mut preimage = leaf_uint.clone();
        for _ in 1..self.modulus_len / batch_size {
            preimage <<= self.bit_size as usize * batch_size;
            preimage += &leaf_uint;
        }
        assert!(&preimage < &self.modulus);
    
        preimage
    }

    pub fn gen_quotient_array(
        &self,
        quotient: BigUint,
    ) -> Vec<BigUint> {
        let base = BigUint::from(1u64) << self.bit_size;
        let mut rest = quotient;
        (0..self.modulus_len).into_iter().map(|_| {
            let (hi, lo) = rest.div_rem(&base);
            rest = hi;

            lo
        }).collect::<Vec<_>>()
    }

    pub fn gen_cypher_array<F: PrimeField>(
        &self,
        cypher: BigUint,
    ) -> Vec<F> {
        let cypher_bits = self.cypher_batch * (self.bit_size as usize);
        assert!(cypher_bits < F::Params::MODULUS_BITS as usize);
        assert_eq!(self.modulus_len % self.cypher_batch, 0);

        let base = BigUint::from(1u64) << cypher_bits;
        let mut rest = cypher;
    
        let res = (0..self.modulus_len / self.cypher_batch).into_iter().map(|_| {
            let (hi, lo) = rest.div_rem(&base);
            rest = hi;
            F::from(lo)
        }).collect::<Vec<_>>();
        assert_eq!(rest, BigUint::from(0u64));
    
        res
    }
}
