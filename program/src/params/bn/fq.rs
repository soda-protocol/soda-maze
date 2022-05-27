use crate::bn::{BigInteger256 as BigInteger, Fp256};
use crate::bn::{Fp256Parameters, FpParameters};

pub const FQ_TWO_INV: &'static Fq = &Fq::new(BigInteger([
    9781510331150239090,
    15059239858463337189,
    10331104244869713732,
    2249375503248834476,
]));

pub type Fq = Fp256<FqParameters>;

pub struct FqParameters;

impl Fp256Parameters for FqParameters {}

impl FpParameters for FqParameters {
    type BigInteger = BigInteger;

    /// MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    const MODULUS: Self::BigInteger = BigInteger::new([
        4332616871279656263,
        10917124144477883021,
        13281191951274694749,
        3486998266802970665,
    ]);

    const MODULUS_BITS: u32 = 254;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 2;

    const R: Self::BigInteger = BigInteger::new([
        15230403791020821917,
        754611498739239741,
        7381016538464732716,
        1011752739694698287,
    ]);

    const R2: Self::BigInteger = BigInteger::new([
        17522657719365597833,
        13107472804851548667,
        5164255478447964150,
        493319470278259999,
    ]);

    const INV: u64 = 9786893198990664585;

    // GENERATOR = 3
    const GENERATOR: Self::BigInteger = BigInteger::new([
        8797723225643362519,
        2263834496217719225,
        3696305541684646532,
        3035258219084094862,
    ]);

    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInteger = BigInteger::new([
        11389680472494603939,
        14681934109093717318,
        15863968012492123182,
        1743499133401485332,
    ]);

    // T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T

    // T = (MODULUS - 1) // 2^S =
    // 10944121435919637611123202872628637544348155578648911831344518947322613104291
    const T: Self::BigInteger = BigInteger::new([
        11389680472494603939,
        14681934109093717318,
        15863968012492123182,
        1743499133401485332,
    ]);

    // (T - 1) // 2 =
    // 5472060717959818805561601436314318772174077789324455915672259473661306552145
    const T_MINUS_ONE_DIV_TWO: Self::BigInteger = BigInteger::new([
        5694840236247301969,
        7340967054546858659,
        7931984006246061591,
        871749566700742666,
    ]);
}

pub const FQ_ZERO: Fq = Fq::new(BigInteger::new([0, 0, 0, 0]));

pub const FQ_ONE: Fq = Fq::new(BigInteger::new([
    15230403791020821917,
    754611498739239741,
    7381016538464732716,
    1011752739694698287,
]));

#[cfg(test)]
mod tests {
    use num_traits::One;

    use crate::bn::Field;

    use super::Fq;

    #[test]
    fn test_two_inv() {
        let two_inv = Fq::one().double().inverse().unwrap();

        println!("{:?}", two_inv.0.0);
    }
}