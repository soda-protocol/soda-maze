use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, entrypoint::ProgramResult};

use crate::error::MazeError;
use crate::params::verify::PreparedVerifyingKey;
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
                msg!("Proving stage: Preparing Inputs of index {}", pi.input_index);
                pi.process(pvk)
            },
            Program::MillerLoop(ml) => {
                msg!("Proving stage: Miller Loop Evaluating");
                ml.process(pvk)
            },
            Program::MillerLoopFinalize(mlf) => {
                msg!("Proving stage: Miller Loop Finalizing");
                mlf.process(pvk)
            },
            Program::FinalExponentEasyPart(fee) => {
                msg!("Proving stage: Final Exponent for Easy Part");
                fee.process()
            },
            Program::FinalExponentHardPart1(feh1) => {
                msg!("Proving stage: Final Exponent for Hard Part I");
                feh1.process()
            },
            Program::FinalExponentHardPart2(feh2) => {
                msg!("Proving stage: Final Exponent for Hard Part II");
                feh2.process()
            },
            Program::FinalExponentHardPart3(feh3) => {
                msg!("Proving stage: Final Exponent for Hard Part III");
                feh3.process()
            },
            Program::FinalExponentHardPart4(feh4) => {
                msg!("Proving stage: Final Exponent for Hard Part IV");
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