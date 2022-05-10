use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use num_bigint::BigUint;

use self::encrypt::{MODULUS, BIT_SIZE};

pub mod uint;
pub mod poly;
pub mod encrypt;

pub struct RabinCircuit<F: PrimeField> {
    quotient: BigUint,
    cypher: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RabinCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // alloc constant
        let modulus = encrypt::biguint_to_const_poly_array::<F, BIT_SIZE>(&MODULUS);
        // alloc input
        let fp_cypher = self.cypher
            .into_iter()
            .map(|v| FpVar::new_input(cs.clone(), || Ok(v)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;


        
            
        


        Ok(())
    }
}

