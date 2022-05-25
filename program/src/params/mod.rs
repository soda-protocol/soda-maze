pub mod bn;
pub mod default_nodes;
pub mod rabin;
pub mod vk;

use borsh::{BorshSerialize, BorshDeserialize};

pub const HEIGHT: usize = 27;

const DEPOSIT_INPUTS: usize = 45;

const WITHDRAW_INPUTS: usize = 40;

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

    pub const fn pvk(&self) -> &vk::PreparedVerifyingKey {
        match self {
            ProofType::Deposit => &vk::PreparedVerifyingKey {
                g_ic_init: vk::deposit::G_IC_INIT,
                gamma_abc_g1: vk::deposit::GAMMA_ABC_G1,
                alpha_g1_beta_g2: vk::deposit::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: vk::deposit::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: vk::deposit::DELTA_G2_NEG_PC,
            },
            // TODO: implement withdraw
            ProofType::Withdraw => &vk::PreparedVerifyingKey {
                g_ic_init: vk::withdraw::G_IC_INIT,
                gamma_abc_g1: vk::withdraw::GAMMA_ABC_G1,
                alpha_g1_beta_g2: vk::withdraw::ALPHA_G1_BETA_G2,
                gamma_g2_neg_pc: vk::withdraw::GAMMA_G2_NEG_PC,
                delta_g2_neg_pc: vk::withdraw::DELTA_G2_NEG_PC,
            }
        }
    }
}