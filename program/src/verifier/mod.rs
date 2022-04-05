pub mod store;
pub mod context;
pub mod pda;
pub mod fsm;
pub mod vanilla;

use std::ops::AddAssign;

use num_traits::Zero;
use solana_program::{entrypoint::ProgramResult, account_info::{AccountInfo, next_account_info}, pubkey::Pubkey, clock::Clock, sysvar::Sysvar, program_error::ProgramError};

use crate::{bn::{G1Affine, G1Prepared, G1Projective, BigInteger256 as BigInteger, BitIteratorBE, Fqk}, Packer, OperationType};
use crate::error::MazeError;

use fsm::{VerifyStage, PublicInputBuffer, VerifyingBuffer, Proof};
use crate::params::{Fr, Bn254Parameters as BnParameters};

// #[inline(never)]
// fn process(
//     verify_buffer: VerifyingBuffer,
//     pubin_buffer: PublicInputBuffer,
//     proof: Proof,
// ) -> Option<VerifyStage> {
//     let stage = verify_buffer.stage;

//     match stage {
//         VerifyStage::CompressInputs {
//             mut input_index,
//             mut g_ic,
//             mut bit_index,
//             mut tmp,
//         } => {
//             let public_input = pubin_buffer.public_inputs[input_index as usize];
//             let bits = BitIteratorBE::new(public_input).skip_while(|b| !b).collect::<Vec<_>>();

//             const MAX_COMPRESS_CYCLE: usize = 4;
//             let start = bit_index as usize;
//             let end = start + MAX_COMPRESS_CYCLE;
//             let (end, finished) = if end < bits.len() {
//                 (end, false)
//             } else {
//                 (bits.len(), true)
//             };

//             let pvk = pubin_buffer.proof_type.verifying_key();
//             for bit in &bits[start..end] {
//                 tmp.double_in_place();
//                 if *bit {
//                     tmp.add_assign_mixed(&pvk.gamma_abc_g1[input_index as usize]);
//                 }
//             }

//             if finished {
//                 g_ic.add_assign(&tmp);
//                 input_index += 1;
//                 if pubin_buffer.public_inputs.get(input_index as usize).is_some() {
//                     bit_index = 0;
//                     tmp = G1Projective::<BnParameters>::zero();
//                     g_ic = pvk.g_ic_init;

//                     Some(VerifyStage::CompressInputs {
//                         input_index,
//                         g_ic,
//                         bit_index,
//                         tmp,
//                     })
//                 } else {
//                     Some(VerifyStage::TrimInputs {
//                         prepared_input: g_ic,
//                         proof_type: pubin_buffer.proof_type,
//                     })
//                 }
//             } else {
//                 Some(VerifyStage::CompressInputs {
//                     input_index,
//                     g_ic,
//                     bit_index: end as u8,
//                     tmp,
//                 })
//             }
//         }
//         VerifyStage::TrimInputs {
//             prepared_input,
//             proof_type,
//         } => {
//             let prepared_input: G1Prepared<BnParameters> = G1Affine::<BnParameters>::from(prepared_input).into();
//             let pvk = proof_type.verifying_key();
            
//             let inputs = [
//                 (proof.a.into(), proof.b.into()),
//                 (
//                     prepared_input,
//                     pvk.gamma_g2_neg_pc.clone(),
//                 ),
//                 (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
//             ];

//             let mut pairs = vec![];
//             for (p, q) in inputs {
//                 if !p.is_zero() && !q.is_zero() {
//                     pairs.push((p, q.ell_coeffs));
//                 }
//             }

//             Some(VerifyStage::MillerLoop {
//                 step: 0,
//                 pairs,
//                 f: Fqk::<BnParameters>::zero(),
//             })
//         }
//         _ => None,
//     }
// }

