mod g1;
mod g2;
mod group;

pub use g1::*;
pub use g2::*;
pub use group::*;

use super::{Fp2, Fp2Parameters, Fp6Parameters, Field, Fp12Parameters, Fp12};

pub enum TwistType {
    M,
    D,
}

pub type Fqk<P> = Fp12<<P as BnParameters>::Fp12Params>;

pub trait ModelParameters: 'static + Clone + Copy {
    type BaseField: Field;
    type ScalarField: Field + AsRef<[u64]>;

    const COEFF_A: Self::BaseField;
    const COEFF_B: Self::BaseField;

    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy *= &Self::COEFF_A;
        copy
    }
}

pub trait BnParameters: 'static {
    const NAF: &'static [i8];
    // Whether or not `X` is negative.
    const X_IS_NEGATIVE: bool;

    // The absolute value of `6X + 2`.
    const ATE_LOOP_COUNT: &'static [i8];

    const TWIST_TYPE: TwistType;
    const TWIST_MUL_BY_Q_X: Fp2<Self::Fp2Params>;
    const TWIST_MUL_BY_Q_Y: Fp2<Self::Fp2Params>;
    
    type Fp: Field;
    type Fp2Params: Fp2Parameters<Fp = Self::Fp>;
    type Fp6Params: Fp6Parameters<Fp2Params = Self::Fp2Params>;
    type Fp12Params: Fp12Parameters<Fp6Params = Self::Fp6Params>;
    type G1Parameters: ModelParameters<BaseField = Self::Fp>;
    type G2Parameters: ModelParameters<BaseField = Fp2<Self::Fp2Params>>;
}

// pub trait PairingEngine {
//     type Fr: Field;
//     type G1Projective: Clone + BorshSerialize + BorshDeserialize;
//     type G2Projective: BorshSerialize + BorshDeserialize;
//     type G1Affine:  BorshSerialize + BorshDeserialize;
//     type G2Affine:  BorshSerialize + BorshDeserialize;
//     type G1Prepared: BorshSerialize + BorshDeserialize + 'static;
//     type G2Prepared: BorshSerialize + BorshDeserialize + 'static;
//     type Fqk: Field;

//     /// Compute the product of miller loops for some number of (G1, G2) pairs.
//     #[must_use]
//     fn miller_loop<'a, I>(i: I) -> Self::Fqk
//     where
//         I: IntoIterator<Item = &'a (Self::G1Prepared, Self::G2Prepared)>;

//     /// Perform final exponentiation of the result of a miller loop.
//     #[must_use]
//     fn final_exponentiation(_: &Self::Fqk) -> Option<Self::Fqk>;
// }
