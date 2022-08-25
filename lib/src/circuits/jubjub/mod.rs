mod point;

use std::marker::PhantomData;
use std::rc::Rc;

use ark_ff::{Field, PrimeField};
use ark_ec::models::{ModelParameters, TEModelParameters};
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;

// /// Reference to a circuit version of a generator for fixed-base salar multiplication.
// pub type FixedGenerator<F: PrimeField> = &'static [Vec<(F, F)>];

pub struct JubjubConstParams<P: TEModelParameters>
where
    <P as ModelParameters>::BaseField: PrimeField,
{
    pubkey: AffineVar<P, FpVar<P::BaseField>>,
}

// pub struct JubjubEncryption<T: TEModelParameters> {
//     params: Rc<JubjubConstParams<T::ScalarField>>,

// }
