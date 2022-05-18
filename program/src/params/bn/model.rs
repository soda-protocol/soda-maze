use crate::bn::{ModelParameters, BigInteger256 as BigInteger};

use super::{Fq, Fr, FQ_ZERO, Fq2, FQ2_ZERO};

#[derive(Clone, Copy)]
pub struct G1Parameters;

impl ModelParameters for G1Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COEFF_A: Fq = FQ_ZERO;
    const COEFF_B: Fq = Fq::new(BigInteger::new([
        8797723225643362519,
        2263834496217719225,
        3696305541684646532,
        3035258219084094862,
    ]));
}

#[derive(Clone, Copy)]
pub struct G2Parameters;

impl ModelParameters for G2Parameters {
    type BaseField = Fq2;
    type ScalarField = Fr;

    const COEFF_A: Fq2 = FQ2_ZERO;
    const COEFF_B: Fq2 = Fq2::new_const(
        Fq::new(BigInteger::new([
            4321547867055981224,
            147241268046680925,
            2789960110459671136,
            2671978398120978541,
        ])),
        Fq::new(BigInteger::new([
            4100506350182530919,
            7345568344173317438,
            15513160039642431658,
            90557763186888013,
        ])),
    );
}