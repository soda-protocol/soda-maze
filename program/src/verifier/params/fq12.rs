
use crate::bn::{Fp12, Fp12Parameters, BigInteger256 as BigInteger};

use super::{Fq6Parameters, Fq6, FQ2_ZERO, FQ2_ONE, Fq2, Fq, FQ_ZERO};

pub type Fq12 = Fp12<Fq12Parameters>;

#[derive(Clone, Copy)]
pub struct Fq12Parameters;

impl Fp12Parameters for Fq12Parameters {
    type Fp6Params = Fq6Parameters;

    const NONRESIDUE: Fq6 = Fq6::new_const(FQ2_ZERO, FQ2_ONE, FQ2_ZERO);

    const FROBENIUS_COEFF_FP12_C1: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^(((q^0) - 1) / 6)
        FQ2_ONE,
        // Fp2::NONRESIDUE^(((q^1) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                12653890742059813127,
                14585784200204367754,
                1278438861261381767,
                212598772761311868,
            ])),
            Fq::new(BigInteger::new([
                11683091849979440498,
                14992204589386555739,
                15866167890766973222,
                1200023580730561873,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                14595462726357228530,
                17349508522658994025,
                1017833795229664280,
                299787779797702374,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                3914496794763385213,
                790120733010914719,
                7322192392869644725,
                581366264293887267,
            ])),
            Fq::new(BigInteger::new([
                12817045492518885689,
                4440270538777280383,
                11178533038884588256,
                2767537931541304486,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                3697675806616062876,
                9065277094688085689,
                6918009208039626314,
                2775033306905974752,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                9707350126413123702,
                4651080606516098580,
                6043753531608262957,
                368767491532575399,
            ])),
            Fq::new(BigInteger::new([
                1133953642539445191,
                7894810023100276260,
                13759109221827166649,
                1567514350810742612,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^6) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                7548957153968385962,
                10162512645738643279,
                5900175412809962033,
                2475245527108272378,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^7) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                10125470202929394752,
                14778084017983066882,
                12002753090013312981,
                3274399494041658797,
            ])),
            Fq::new(BigInteger::new([
                11096269095009767381,
                14371663628800878897,
                15861768134217273142,
                2286974686072408791,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^8) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                8183898218631979349,
                12014359695528440611,
                12263358156045030468,
                3187210487005268291,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^9) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                418120076516271050,
                10127003411466968302,
                5958999558405050024,
                2905632002509083398,
            ])),
            Fq::new(BigInteger::new([
                9962315452470322190,
                6476853605700602637,
                2102658912390106493,
                719460335261666179,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^10) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                634941064663593387,
                1851847049789797332,
                6363182743235068435,
                711964959896995913,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^11) - 1) / 6)
        Fq2::new_const(
            Fq::new(BigInteger::new([
                13072010818576084177,
                6266043537961784440,
                7237438419666431792,
                3118230775270395266,
            ])),
            Fq::new(BigInteger::new([
                3198663228740211072,
                3022314121377606761,
                17968826803157079716,
                1919483915992228052,
            ])),
        ),
    ];
}
