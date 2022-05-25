use borsh::{BorshSerialize, BorshDeserialize};

use crate::params::vk::PreparedVerifyingKey;
use super::prepare_inputs::*;
use super::miller_loop::*;
use super::final_exponent::*;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum FSM {
    PrepareInputs(PrepareInputs),
    MillerLoop(MillerLoop),
    MillerLoopFinalize(MillerLoopFinalize),
    FinalExponentEasyPart(FinalExponentEasyPart),
    FinalExponentHardPart1(FinalExponentHardPart1),
    FinalExponentHardPart2(FinalExponentHardPart2),
    FinalExponentHardPart3(FinalExponentHardPart3),
    FinalExponentHardPart4(FinalExponentHardPart4),
    Finished(bool),
}

impl FSM {
    #[inline(never)]
    pub fn process(self, pvk: &PreparedVerifyingKey) -> Self {
        match self {
            FSM::PrepareInputs(pi) => pi.process(pvk),
            FSM::MillerLoop(ml) => ml.process(pvk),
            FSM::MillerLoopFinalize(mlf) => mlf.process(pvk),
            FSM::FinalExponentEasyPart(fee) => fee.process(),
            FSM::FinalExponentHardPart1(feh1) => feh1.process(),
            FSM::FinalExponentHardPart2(feh2) => feh2.process(),
            FSM::FinalExponentHardPart3(feh3) => feh3.process(),
            FSM::FinalExponentHardPart4(feh4) => feh4.process(pvk),
            FSM::Finished(f) => FSM::Finished(f),
        }
    }
}