// pub mod uint126;
pub mod array;
pub mod uint;
pub mod uint2;
pub mod array2;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};

use self::uint::GeneralUint;

// use self::uint126::Uint126;

// use super::uint126::U126;

type U126<F> = GeneralUint<F, BIT_SIZE>;

pub const BIT_SIZE: u32 = 126;
pub const PRIME_LENGTH: usize = 12;
pub const MODULUS_LENGTH: usize = PRIME_LENGTH * 2;
pub const MODULUS: [u128; MODULUS_LENGTH] = [
    5217175804021272938173857639386470627,
    20504512440984368570375634982842649736,
    14980320213494055727945337635945708328,
    16095228728332069921862925763157718822,
    22563912901485625892903404409719671456,
    67174084442812919276451341121897694851,
    396210734289974881854329569352686287,
    68026446314505966650746423272869188619,
    33163016477865278193781760969995298508,
    38752055472634785082752047412861813264,
    77700377108864573542735925507345108658,
    9639361772306058418440018209226451648,
    79644271933641188650826466460393731827,
    12432924080713375365389497117979402200,
    73973061915451825917866479557478222941,
    67743906593044375400837886364440623418,
    39836218244962850066907990555682860487,
    81187501433027136684536554726744555131,
    13023821752885007423488901562417721737,
    39445900292978958344332733832851030135,
    13650824604776585941445191602831633714,
    21292839498938940799997982088923194589,
    19666570999405728435609406136312941565,
    69910805009745807039180465907423838473,
];

// preimage = leaf_0 | leaf_1 | leaf_2 | ... ... | leaf_0 | leaf_1 | leaf_2
//            \-----------------------------\/----------------------------/
//                                     8 leaf in loop
pub fn generate_preimage<F: PrimeField>(
    leaf: FpVar<F>,
) -> Result<Vec<U126<F>>, SynthesisError> {
    let vars = GeneralUint::from_fp_var(leaf)?;
    assert_eq!(vars.len(), 3);
    assert!(vars[2].value()? < MODULUS[MODULUS_LENGTH - 1]);

    let mut preimage = Vec::with_capacity(MODULUS_LENGTH);
    for _ in 0..(MODULUS_LENGTH / vars.len()) {
        preimage.extend_from_slice(&vars);
    }

    Ok(preimage)
}



/////////////////////////////////////////
// quotient * modulus + e = m^2
// e + s = modulus => e < modulus
// pub fn verify_rabin_encryption<F: PrimeField>(
//     cs: ConstraintSystemRef<F>,
//     index: FpVar<F>,
//     secret: FpVar<F>,
//     quotient: Vec<U126>,
//     s: Vec<U126>,
//     e: Vec<F>,
// ) -> Result<(), SynthesisError> {
//     assert_eq!(quotient.len(), MODULUS_LENGTH);
//     assert_eq!(e.len(), MODULUS_LENGTH);

//     let quotient_var = quotient
//         .into_iter()
//         .map(|q| Uint126::new_witness(cs.clone(), || Ok(q)))
//         .collect::<Result<Vec<_>, SynthesisError>>()?;

    

//     Ok(())
// }

#[cfg(test)]
mod tests {
    use num_traits::{FromPrimitive, ToPrimitive};
    use rsa::algorithms::generate_multi_prime_key_with_exp;
    use ark_std::{test_rng, rand::prelude::StdRng};
    use num_bigint_dig::{RandPrime, BigUint};

    use crate::circuits::rabin::MODULUS_LENGTH;

    #[test]
    fn test_prime_key() {
        let rng = &mut test_rng();

        let p = rng.gen_prime(1512);
        let q = rng.gen_prime(1512);
        let ref n = p * q;

        let ref mask = BigUint::from_u128(0x3FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128).unwrap();
        let res = (0..MODULUS_LENGTH).into_iter().map(|i| {
            let v = (n >> (MODULUS_LENGTH * i)) & mask;
            v.to_u128().unwrap()
        }).collect::<Vec<_>>();

        println!("{:?}", res);
    }
}