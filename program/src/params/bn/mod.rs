mod fr;
mod fq;
mod fq2;
mod fq6;
mod fq12;
mod model;

pub use fr::*;
pub use fq::*;
pub use fq2::*;
pub use fq6::*;
pub use fq12::*;
pub use model::*;

use std::marker::PhantomData;

use crate::bn::{
    BnParameters, TwistType, BigInteger256 as BigInteger,
    G1Projective, G2Projective, G1Affine, G2Affine,
    G2Prepared, EllCoeff, Fqk, G2HomProjective,
};

#[derive(Clone, Copy)]
pub struct Bn254Parameters;

impl BnParameters for Bn254Parameters {
    const NAF_INV: &'static [i8] = &[
        1, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, -1, 0, -1, 0, -1, 0, 1, 0, 0,
        0, 1, 0, 0, 1, 0, 1, 0, 1, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 1,
    ];

    const X_IS_NEGATIVE: bool = false;

    const ATE_LOOP_COUNT_INV: &'static [i8] = &[
        1, 0, 1, 0, 0, -1, 0, 1, 1, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 1,
        1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, 0, 1, 1, 0, 0, 1, 0, 0, -1, 1, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0,
    ];

    const TWIST_TYPE: TwistType = TwistType::D;

    const TWIST_MUL_BY_Q_X: Fq2 = Fq2::new_const(
        Fq::new(BigInteger::new([
            13075984984163199792,
            3782902503040509012,
            8791150885551868305,
            1825854335138010348,
        ])),
        Fq::new(BigInteger::new([
            7963664994991228759,
            12257807996192067905,
            13179524609921305146,
            2767831111890561987,
        ])),
    );

    const TWIST_MUL_BY_Q_Y: Fq2 = Fq2::new_const(
        Fq::new(BigInteger::new([
            16482010305593259561,
            13488546290961988299,
            3578621962720924518,
            2681173117283399901,
        ])),
        Fq::new(BigInteger::new([
            11661927080404088775,
            553939530661941723,
            7860678177968807019,
            3208568454732775116,
        ])),
    );

    type Fp = Fq;
    type Fp2Params = Fq2Parameters;
    type Fp6Params = Fq6Parameters;
    type Fp12Params = Fq12Parameters;
    type G1Parameters = G1Parameters;
    type G2Parameters = G2Parameters;
}

pub type G1Projective254 = G1Projective<Bn254Parameters>;

impl G1Projective254 {
    pub const fn new_const(
        x: Fq,
        y: Fq,
        z: Fq,
    ) -> Self {
        Self { x, y, z, _p: PhantomData }   
    }
}

pub type G2Projective254 = G2Projective<Bn254Parameters>;

impl G2Projective254 {
    pub const fn new_const(
        x: Fq2,
        y: Fq2,
        z: Fq2,
    ) -> Self {
        Self { x, y, z, _p: PhantomData }   
    }
}

pub type G1Affine254 = G1Affine<Bn254Parameters>;

impl G1Affine254 {
    pub const fn new_const(
        x: Fq,
        y: Fq,
        infinity: bool,
    ) -> Self {
        Self { x, y, infinity, _p: PhantomData }   
    }
}

pub type G2Affine254 = G2Affine<Bn254Parameters>;

impl G2Affine254 {
    pub const fn new_const(
        x: Fq2,
        y: Fq2,
        infinity: bool,
    ) -> Self {
        Self { x, y, infinity, _p: PhantomData }   
    }
}

pub type EllCoeffFq2 = EllCoeff<Fq2>;

pub type G2Prepared254 = G2Prepared<Bn254Parameters>;

impl G2Prepared254 {
    pub const fn new_const(
        ell_coeffs: Vec<EllCoeffFq2>,
        infinity: bool,
    ) -> Self {
        Self { ell_coeffs, infinity }
    }
}

pub type Fqk254 = Fqk<Bn254Parameters>;

impl Fqk254 {
    pub const fn new_const(
        c0: Fq6,
        c1: Fq6,
    ) -> Self {
        Self { c0, c1, _p: PhantomData }
    }
}

pub type G2HomProjective254 = G2HomProjective<Bn254Parameters>;
