use std::marker::PhantomData;

use crate::bn::{Fp2Parameters, BigInteger256 as BigInteger, Fp2, Fp2ParamsWrapper, QuadExtParameters};
use super::{Fq, FQ_ONE, FQ_ZERO};

pub type Fq2 = Fp2<Fq2Parameters>;

impl Fq2 {
    pub const fn new_const(
        c0: <Fp2ParamsWrapper<Fq2Parameters> as QuadExtParameters>::BaseField,
        c1: <Fp2ParamsWrapper<Fq2Parameters> as QuadExtParameters>::BaseField,
    ) -> Self {
        Self { c0, c1, _p: PhantomData }
    }
}

#[derive(Clone, Copy)]
pub struct Fq2Parameters;

impl Fp2Parameters for Fq2Parameters {
    type Fp = Fq;

    /// NONRESIDUE = -1
    const NONRESIDUE: Fq = Fq::new(BigInteger::new([
        7548957153968385962,
        10162512645738643279,
        5900175412809962033,
        2475245527108272378,
    ]));

    /// QUADRATIC_NONRESIDUE = U+2
    const QUADRATIC_NONRESIDUE: (Fq, Fq) = (
        Fq::new(BigInteger::new([
            12014063508332092218,
            1509222997478479483,
            14762033076929465432,
            2023505479389396574,
        ])),
        FQ_ONE,
    );

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_FP2_C1: &'static [Fq] = &[
        // NONRESIDUE**(((q^0) - 1) / 2)
        FQ_ONE,
        // NONRESIDUE**(((q^1) - 1) / 2)
        Fq::new(BigInteger::new([
            7548957153968385962,
            10162512645738643279,
            5900175412809962033,
            2475245527108272378,
        ])),
    ];

    #[inline(always)]
    fn mul_fp_by_nonresidue(fe: &Self::Fp) -> Self::Fp {
        -(*fe)
    }
}

pub const FQ2_ZERO: Fq2 = Fq2::new_const(FQ_ZERO, FQ_ZERO);
pub const FQ2_ONE: Fq2 = Fq2::new_const(FQ_ONE, FQ_ZERO);