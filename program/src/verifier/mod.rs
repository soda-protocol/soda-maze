pub mod state;
pub mod params;
pub mod key;

use core::ops::AddAssign;

use solana_program::{entrypoint::ProgramResult, account_info::{AccountInfo, next_account_info}, pubkey::Pubkey, clock::Clock, sysvar::Sysvar};

use crate::{bn::{BnParameters, ModelParameters, G1Affine, G1Prepared, G1Projective, BigInteger256 as BigInteger}, Packer};
use crate::error::MazeError;

use self::state::{VerifyStage, PreparedVerifyingKey};

use params::{Fr, Fq, FqParameters, BN254Parameters};

pub fn process_test() {
    let fq_x = Fq::new(BigInteger::new([1920615429724524877, 4486917021698251311, 15645255062489922141, 2227445642710651851]));
    let fq_y = Fq::new(BigInteger::new([8407339625123927062, 8256482775165990740, 17200014529260685901, 3184573262101794352]));

    let gamma_abc_g1 = G1Affine::<BN254Parameters>::new(fq_x, fq_y, false);
    let public_input = Fr::new(BigInteger::new([3928200423253467360, 4267233211940291711, 12969216809553785426, 1454720173490149085]));
    let mut g_ic = G1Projective::<BN254Parameters>::new(
        Fq::new(BigInteger::new([15377002934136960886, 5560867096201794898, 10007675410708381178, 3046086368553324590])),
        Fq::new(BigInteger::new([11672019301395092212, 3808594006677137504, 9755693271842704518, 1421258029962603853])),
        Fq::new(BigInteger::new([7188505923352453205, 119776587197042243, 8013636411937465998, 2654000331269309751])),
    );

    g_ic.add_assign(&gamma_abc_g1.mul(public_input));
}

// #[cfg(test)]
// mod tests {
//     use rand::prelude::ThreadRng;
//     use solana_program::{log::sol_log_compute_units, program_stubs::set_syscall_stubs};
//     use rand::{thread_rng, Rng};
//     use rand::distributions::Standard;
    
//     use crate::bn::{G1Affine, BigInteger256 as BigInteger, FpParameters, G1Projective};
//     use crate::verifier::params::{BN254Parameters, FrParameters};
//     use super::params::{Fr, Fq, FqParameters};

//     fn rand_integer(rng: &mut ThreadRng) -> [u64; 4] {
//         let mut value = rng.sample::<[u64; 4], _>(Standard);

//         loop {
//             if value[3] >= <FrParameters as FpParameters>::MODULUS.0[3] {
//                 value[3] >>= 1;
//             } else {
//                 break;
//             }
//         }

//         println!("{:?}", &value);

//         value
//     }

//     #[test]
//     fn test_prepare_inputs() {
//         let mut rng = thread_rng();

//         let fq_x = Fq::new(BigInteger::new(rand_integer(&mut rng)));
//         let fq_y = Fq::new(BigInteger::new(rand_integer(&mut rng)));

//         let gamma_abc_g1 = G1Affine::<BN254Parameters>::new(fq_x, fq_y, false);
//         let public_input = Fr::new(BigInteger::new([3928200423253467360, 4267233211940291711, 12969216809553785426, 1454720173490149085]));
//         let mut g_ic = G1Projective::<BN254Parameters>::new(
//             Fq::new(BigInteger::new(rand_integer(&mut rng))),
//             Fq::new(BigInteger::new(rand_integer(&mut rng))),
//             Fq::new(BigInteger::new(rand_integer(&mut rng))),
//         );
//     }
// }
