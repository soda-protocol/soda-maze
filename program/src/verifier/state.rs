use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

use crate::{bn::{G1Projective, G1Affine, G1Prepared, G2Affine, G2Prepared, Fqk, EllCoeff, G2HomProjective}, Packer, OperationType};
use super::params::{Fr, Bn254Parameters as BnParameters, Fq2, G1Projective254, G1Affine254};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Proof {
    /// The `A` element in `G1`.
    pub a: G1Affine<BnParameters>,
    /// The `B` element in `G2`.
    pub b: G2Affine<BnParameters>,
    /// The `C` element in `G1`.
    pub c: G1Affine<BnParameters>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum VerifyStage {
    CompressInputs {
        input_index: u8,
        g_ic: G1Projective<BnParameters>,
        bit_index: u8,
        tmp: G1Projective<BnParameters>,
    },
    PrepareInput {
        compressed_input: G1Projective<BnParameters>,
        proof_type: OperationType,
    },
    MillerLoop {
        index: u8,
        coeff_index: u8,
        proof_type: OperationType,
        prepared_input: G1Affine<BnParameters>,
        rb: G2HomProjective<BnParameters>,
        negb: G2Affine<BnParameters>,
        f: Fqk<BnParameters>,
    },
    FinalExponent(Fqk<BnParameters>),
    Verified,
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