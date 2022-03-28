use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{clock::Slot, program_pack::IsInitialized, pubkey::Pubkey};

use crate::{bn::{G1Projective, BnParameters, G1Affine, Fqk, G2Prepared, G1Prepared, G2Affine, ModelParameters}, Packer, HEIGHT, OperationType};

pub type Fr<P> = <<P as BnParameters>::G1Parameters as ModelParameters>::ScalarField;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PreparedVerifyingKey<P: BnParameters> {
    ///
    pub g_ic_init: G1Projective<P>,
    /// The unprepared verification key.
    pub gamma_abc_g1: Vec<G1Affine<P>>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: Fqk<P>,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: G2Prepared<P>,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: G2Prepared<P>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof<P: BnParameters> {
    /// The `A` element in `G1`.
    pub a: G1Affine<P>,
    /// The `B` element in `G2`.
    pub b: G2Affine<P>,
    /// The `C` element in `G1`.
    pub c: G1Affine<P>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum VerifyStage<P: BnParameters> {
    HandlingInputs {
        step: usize,
        g_ic: G1Projective<P>,
    },
    FinishedInputs {
        prepared_input: G1Projective<P>,
        proof_type: OperationType,
    },
    MillerLoop {
        step: usize,
        pairs: Vec<(G1Prepared<P>, G2Prepared<P>)>,
        f: Fqk<P>,
    },
    FinalExponent(Fqk<P>),
    Verified,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PublicInputBuffer<P: BnParameters> {
    pub is_initialized: bool,
    pub proof_type: OperationType,
    pub public_inputs: Vec<Fr<P>>,
    pub owner: Pubkey,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VerifyingBuffer<P: BnParameters> {
    pub is_initialized: bool,
    pub public_input: Pubkey,
    pub stage: VerifyStage<P>,
}

// pub enum VanillaData<P: BnParameters> {
//     Deposit {
//         mint: Pubkey,
//         deposit_amount: u64,
//         old_root: Fr<P>,
//         leaf: Fr<P>,
//         leaf_index: u32,
//         update_nodes: [Fr<P>; HEIGHT],
//     },
//     Withdraw {
//         mint: Pubkey,
//         withdraw_amount: u64,
//         old_root: Fr<P>,
//         new_leaf: Fr<P>,
//         new_leaf_index: u32,
//         update_nodes: [Fr<P>; HEIGHT],
//     },
// }

impl<P: BnParameters> IsInitialized for VerifyingBuffer<P> {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl<P: BnParameters> Packer for VerifyingBuffer<P> {
    const LEN: usize = 2048;
}