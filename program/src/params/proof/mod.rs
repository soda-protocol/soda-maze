pub mod pvk_deposit;
pub mod pvk_withdraw;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::params::bn::{G1Projective254, G1Affine254, EllCoeffFq2, Fqk254};

const DEPOSIT_INPUTS: usize = 45;

const WITHDRAW_INPUTS: usize = 40;

pub struct PreparedVerifyingKey<'a> {
    /// 
    pub g_ic_init: &'a G1Projective254,
    /// The unprepared verification key.
    pub gamma_abc_g1: &'a [G1Affine254],
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: &'a Fqk254,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: &'a [EllCoeffFq2],
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: &'a [EllCoeffFq2],
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum ProofType {
    Deposit,
    Withdraw,
}

impl ProofType {
    pub const fn inputs_len(&self) -> usize {
        match self {
            ProofType::Deposit => DEPOSIT_INPUTS,
            ProofType::Withdraw => WITHDRAW_INPUTS,
        }
    }

    pub const fn pvk(&self) -> &PreparedVerifyingKey {
        match self {
            ProofType::Deposit => &PreparedVerifyingKey {
                g_ic_init: pvk_deposit::G_IC_INIT,
                gamma_abc_g1: pvk_deposit::GAMMA_ABC_G1,
                alpha_g1_beta_g2: pvk_deposit::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: pvk_deposit::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: pvk_deposit::DELTA_G2_NEG_PC,
            },
            // TODO: implement withdraw
            ProofType::Withdraw => &PreparedVerifyingKey {
                g_ic_init: pvk_withdraw::G_IC_INIT,
                gamma_abc_g1: pvk_withdraw::GAMMA_ABC_G1,
                alpha_g1_beta_g2: pvk_withdraw::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: pvk_withdraw::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: pvk_withdraw::DELTA_G2_NEG_PC,
            }
        }
    }
}
