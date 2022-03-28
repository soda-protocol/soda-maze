pub mod state;
pub mod params;
pub mod key;

use core::ops::AddAssign;

use solana_program::{entrypoint::ProgramResult, account_info::{AccountInfo, next_account_info}, pubkey::Pubkey, clock::Clock, sysvar::Sysvar};

use crate::{bn::{BnParameters, ModelParameters, G1Affine, G1Prepared, G1Projective}, Packer};
use crate::error::MazeError;

use self::state::{VerifyStage, PreparedVerifyingKey};

type Fr<P> = <<P as BnParameters>::G1Parameters as ModelParameters>::ScalarField;

#[inline]
pub fn prepare_inputs<P: BnParameters>(
    gamma_abc_g1: &G1Affine<P>,
    public_input: Fr<P>,
    g_ic: &mut G1Projective<P>,
) {
    g_ic.add_assign(&gamma_abc_g1.mul(public_input));
}

// pub fn process_prepare_input<P: BnParameters, const INPUTS_LEN: usize>(
//     accounts: &[AccountInfo],
//     public_inputs: &[Fr<P>; INPUTS_LEN],
//     gamma_abc_g1: &[G1Affine<P>],
// ) -> ProgramResult {
//     let account_info_iter = &mut accounts.iter();

//     // let clock = Clock::from_account_info(next_account_info(account_info_iter)?)?;
//     let buffer_info = next_account_info(account_info_iter)?;

//     let mut buffer = VerifyBuffer::<P>::unpack(&buffer_info.try_borrow_data()?)?;
//     // if buffer.slot != clock.slot {
//     //     return Err(MazeError::InvalidParam.into());
//     // }

//     if let VerifyStage::PreparingInputs {
//         index,
//         g_ic,
//     } = &mut buffer.verify_stage {
//         let b = gamma_abc_g1[*index];
//         let i = public_inputs[*index];
//         g_ic.add_assign(&b.mul(i));
//         *index += 1;

//         if (*index as usize) >= INPUTS_LEN {
//             buffer.verify_stage = VerifyStage::PreparedInputs { g_ic: *g_ic };
//         }

//         Ok(())
//     } else {
//         Err(MazeError::InvalidParam.into())
//     }
// }

#[cfg(test)]
mod tests {
    use rand::prelude::ThreadRng;
    use solana_program::{msg, log::sol_log_compute_units};
    use rand::{thread_rng, Rng};
    use rand::distributions::Standard;
    
    use crate::bn::{G1Affine, BigInteger256 as BigInteger, FpParameters, G1Projective};
    use crate::verifier::params::BN254Parameters;
    use super::params::{Fr, Fq, FqParameters};
    use super::prepare_inputs;

    fn rand_integer(rng: &mut ThreadRng) -> [u64; 4] {
        let mut value = rng.sample::<[u64; 4], _>(Standard);

        loop {
            if value[3] >= <FqParameters as FpParameters>::MODULUS.0[3] {
                value[3] >>= 1;
            } else {
                break;
            }
        }

        value
    }

    #[test]
    fn test_prepare_inputs() {
        let mut rng = thread_rng();

        let fq_x = Fq::new(BigInteger::new(rand_integer(&mut rng)));
        let fq_y = Fq::new(BigInteger::new(rand_integer(&mut rng)));

        let gamma_abc_g1 = G1Affine::<BN254Parameters>::new(fq_x, fq_y, false);
        let public_input = Fr::new(BigInteger::new(rand_integer(&mut rng)));
        let mut g_ic = G1Projective::<BN254Parameters>::new(
            Fq::new(BigInteger::new(rand_integer(&mut rng))),
            Fq::new(BigInteger::new(rand_integer(&mut rng))),
            Fq::new(BigInteger::new(rand_integer(&mut rng))),
        );
        
        sol_log_compute_units();
        prepare_inputs::<BN254Parameters>(&gamma_abc_g1, public_input, &mut g_ic);
        sol_log_compute_units();
    }
}
