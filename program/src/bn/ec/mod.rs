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
    // inv of find wnaf of X
    const NAF_INV: &'static [i8];
    // Whether or not `X` is negative.
    const X_IS_NEGATIVE: bool;

    // The inv absolute value of `6X + 2`.
    const ATE_LOOP_COUNT_INV: &'static [i8];

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

pub type Fqk<P> = Fp12<<P as BnParameters>::Fp12Params>;
