use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

use crate::{Packer, OperationType};
use super::{params::{Fr, G1Affine254, G2Affine254}, processor::*};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof {
    /// The `A` element in `G1`.
    pub a: G1Affine254,
    /// The `B` element in `G2`.
    pub b: G2Affine254,
    /// The `C` element in `G1`.
    pub c: G1Affine254,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum VerifyStage {
    PrepareInputs(PrepareInputs),
    FinalizeInputs(FinalizeInputs),
    MillerLoop(MillerLoop),
    MillerFinalize(MillerFinalize),
    FinalExponentInverse0(FinalExponentInverse0),
    FinalExponentInverse1(FinalExponentInverse1),
    FinalExponentStep0(FinalExponentStep0),
    FinalExponentStep1(FinalExponentStep1),
    FinalExponentStep2(FinalExponentStep2),
    FinalExponentStep3(FinalExponentStep3),
    FinalExponentStep4(FinalExponentStep4),
    FinalExponentStep5(FinalExponentStep5),
    FinalExponentStep6(FinalExponentStep6),
    Finished(bool),
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PublicInputBuffer {
    pub is_initialized: bool,
    pub owner: Pubkey,
    pub proof_type: OperationType,
    pub public_inputs: Vec<Fr>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct VerifyingBuffer {
    pub is_initialized: bool,
    pub public_input: Pubkey,
    pub stage: VerifyStage,
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

impl IsInitialized for PublicInputBuffer {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for PublicInputBuffer {
    const LEN: usize = 1024;
}

impl IsInitialized for VerifyingBuffer {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for VerifyingBuffer {
    const LEN: usize = 1024;
}