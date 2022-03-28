use crate::bn::{Fp6Parameters, BigInteger256 as BigInteger, Field, Fp2Parameters, Fp6};

use super::{Fq2Parameters, Fq2, Fq, FQ_ONE, FQ_ZERO, FQ2_ONE};

pub type Fq6 = Fp6<Fq6Parameters>;

#[derive(Clone, Copy)]
pub struct Fq6Parameters;

impl Fp6Parameters for Fq6Parameters {
    type Fp2Params = Fq2Parameters;

    /// NONRESIDUE = U+9
    const NONRESIDUE: Fq2 = Fq2::new(
        Fq::new(BigInteger::new([
            17727935934370775031,
            3403999273406943249,
            2973276796214101713,
            2131778123646343255,
        ])),
        FQ_ONE,
    );

    const FROBENIUS_COEFF_FP6_C1: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^(((q^0) - 1) / 3)
        FQ2_ONE,
        // Fp2::NONRESIDUE^(((q^1) - 1) / 3)
        Fq2::new(
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
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                3697675806616062876,
                9065277094688085689,
                6918009208039626314,
                2775033306905974752,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                14532872967180610477,
                12903226530429559474,
                1868623743233345524,
                2316889217940299650,
            ])),
            Fq::new(BigInteger::new([
                12447993766991532972,
                4121872836076202828,
                7630813605053367399,
                740282956577754197,
            ])),
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                8183898218631979349,
                12014359695528440611,
                12263358156045030468,
                3187210487005268291,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                17949863938634605489,
                5148119255485697554,
                15902609273764175669,
                2831252980527631332,
            ])),
            Fq::new(BigInteger::new([
                6700319054286102411,
                5454567456687495308,
                5752045687574716953,
                3465882465137625146,
            ])),
        ),
    ];

    const FROBENIUS_COEFF_FP6_C2: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^((2*(q^0) - 2) / 3)
        FQ2_ONE,
        // Fp2::NONRESIDUE^((2*(q^1) - 2) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                8314163329781907090,
                11942187022798819835,
                11282677263046157209,
                1576150870752482284,
            ])),
            Fq::new(BigInteger::new([
                6763840483288992073,
                7118829427391486816,
                4016233444936635065,
                2630958277570195709,
            ])),
        ),
        // Fp2::NONRESIDUE^((2*(q^2) - 2) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                8183898218631979349,
                12014359695528440611,
                12263358156045030468,
                3187210487005268291,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^((2*(q^3) - 2) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                4938922280314430175,
                13823286637238282975,
                15589480384090068090,
                481952561930628184,
            ])),
            Fq::new(BigInteger::new([
                3105754162722846417,
                11647802298615474591,
                13057042392041828081,
                1660844386505564338,
            ])),
        ),
        // Fp2::NONRESIDUE^((2*(q^4) - 2) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                3697675806616062876,
                9065277094688085689,
                6918009208039626314,
                2775033306905974752,
            ])),
            FQ_ZERO,
        ),
        // Fp2::NONRESIDUE^((2*(q^5) - 2) / 3)
        Fq2::new(
            Fq::new(BigInteger::new([
                9526275334892870614,
                3598394558150331826,
                4855778377848021065,
                1428894834119860196,
            ])),
            Fq::new(BigInteger::new([
                17242383170257025652,
                3067616562948804634,
                9489108065570926352,
                2682193869530181283,
            ])),
        ),
    ];

    #[inline(always)]
    fn mul_fp2_by_nonresidue(fe: &Fq2) -> Fq2 {
        // (c0+u*c1)*(9+u) = (9*c0-c1)+u*(9*c1+c0)
        let mut f = *fe;
        f.double_in_place().double_in_place().double_in_place();
        let c0 = f.c0 + fe.c0 + Fq2Parameters::mul_fp_by_nonresidue(&fe.c1);
        let c1 = f.c1 + fe.c1 + fe.c0;
        
        Fq2::new(c0, c1)
    }
}