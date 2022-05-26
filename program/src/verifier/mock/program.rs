use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, entrypoint::ProgramResult};

use crate::error::MazeError;
use crate::params::proof::PreparedVerifyingKey;
use super::prepare_inputs::*;
use super::miller_loop::*;
use super::final_exponent::*;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Program {
    PrepareInputs(PrepareInputs),
    MillerLoop(MillerLoop),
    MillerLoopFinalize(MillerLoopFinalize),
    FinalExponentEasyPart(FinalExponentEasyPart),
    FinalExponentHardPart1(FinalExponentHardPart1),
    FinalExponentHardPart2(FinalExponentHardPart2),
    FinalExponentHardPart3(FinalExponentHardPart3),
    FinalExponentHardPart4(FinalExponentHardPart4),
    Finish(bool),
}

impl Program {
    #[inline(never)]
    pub fn process(self, pvk: &PreparedVerifyingKey) -> Self {
        match self {
            Program::PrepareInputs(pi) => {
                msg!("Proving stage: Prepare Inputs at input index {}, bit index {}", pi.input_index, pi.bit_index);
                pi.process(pvk)
            },
            Program::MillerLoop(ml) => {
                msg!("Proving stage: Miller Loop at ATE index {}, coeff index {}", ml.ate_index, ml.coeff_index);
                ml.process(pvk)
            },
            Program::MillerLoopFinalize(mlf) => {
                msg!("Proving stage: Miller Loop Finalize");
                mlf.process(pvk)
            },
            Program::FinalExponentEasyPart(fee) => {
                msg!("Proving stage: Final Exponent Easy Part");
                fee.process()
            },
            Program::FinalExponentHardPart1(feh1) => {
                msg!("Proving stage: Final Exponent Hard Part 1 at index {}", feh1.index);
                feh1.process()
            },
            Program::FinalExponentHardPart2(feh2) => {
                msg!("Proving stage: Final Exponent Hard Part 2 at index {}", feh2.index);
                feh2.process()
            },
            Program::FinalExponentHardPart3(feh3) => {
                msg!("Proving stage: Final Exponent Hard Part 3 at index {}", feh3.index);
                feh3.process()
            },
            Program::FinalExponentHardPart4(feh4) => {
                msg!("Proving stage: Final Exponent Hard Part 4");
                feh4.process(pvk)
            },
            Program::Finish(f) => {
                if f {
                    msg!("Proving stage: Proof Verified");
                } else {
                    msg!("Proving stage: Proof Failure");
                }
                Program::Finish(f)
            },
        }
    }

    pub fn check_verified(&self) -> ProgramResult {
        if let Program::Finish(res) = self {
            if *res {
                msg!("Proof Verified");
                Ok(())
            } else {
                msg!("Proof Failure");
                Err(MazeError::ProofNotVerified.into())
            }
        } else {
            msg!("Proof Not Finished");
            Err(MazeError::ProofNotVerified.into())
        }
    }
}