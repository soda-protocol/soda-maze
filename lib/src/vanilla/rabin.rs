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

    // preimage = ... | random | ... | leaf0 | leaf1 | leaf2
    //                  lo -------------------> hi
    pub fn gen_preimage_from_leaf<F: PrimeField>(
        &self,
        leaf: F,
        padding: &[BigUint],
    ) -> BigUint {
        let mut preimage_array = padding.iter().map(|p| {
            assert!(p.bits() <= self.bit_size);
            p.clone()
        }).collect::<Vec<_>>();

        let mut leaf_len = F::Params::MODULUS_BITS as u64 / self.bit_size;
        if F::Params::MODULUS_BITS as u64 % self.bit_size != 0 {
            leaf_len += 1;
        }
        let base = BigUint::from(1u64) << self.bit_size;
        let mut rest: BigUint = leaf.into();
        for _ in 0..leaf_len {
            let (hi, lo) = rest.div_rem(&base);
            rest = hi;
            preimage_array.push(lo);
        }
        assert_eq!(rest, BigUint::from(0u64));
        assert_eq!(preimage_array.len(), self.modulus_len);

        let (preimage, _) = preimage_array.into_iter().fold(
            (BigUint::from(0u64), BigUint::from(1u64)),
            |(value, base), p| {
                let value = value + &base * p;
                let base = base << self.bit_size;
    
                (value, base)
            });

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
