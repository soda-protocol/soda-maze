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

use crate::bn::{BnParameters, TwistType, BigInteger256 as BigInteger};

pub struct BN254Parameters;

impl BnParameters for BN254Parameters {
    const X: &'static [u64] = &[4965661367192848881];

    const X_IS_NEGATIVE: bool = false;

    const ATE_LOOP_COUNT: &'static [i8] = &[
        0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0,
        0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0,
        -1, 0, 0, 1, 0, 1, 1,
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