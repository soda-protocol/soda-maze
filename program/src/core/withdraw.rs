use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, program_error::ProgramError};

use crate::params::{verify::ProofType, HEIGHT};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger};
use super::{pubkey_to_fr_repr, is_fr_valid, is_edwards_affine_valid};
use super::node::is_updating_nodes_valid;
use super::commitment::{is_commitment_valid, InnerCommitment};
use super::{EdwardsAffine, VanillaData, credential::Credential};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawVanillaData {
    pub receiver: Pubkey,
    pub withdraw_amount: u64,
    pub nullifier_point: EdwardsAffine,
    pub leaf_index: u64,
    pub leaf: BigInteger,
    pub prev_root: BigInteger,
    pub updating_nodes: Box<Vec<BigInteger>>,
    pub commitment: InnerCommitment,
}

impl WithdrawVanillaData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: Pubkey,
        withdraw_amount: u64,
        nullifier_point: EdwardsAffine,
        leaf_index: u64,
        leaf: BigInteger,
        prev_root: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
        commitment: InnerCommitment,
    ) -> Result<Self, ProgramError> {
        if !is_edwards_affine_valid(&nullifier_point) {
            msg!("nullifier point is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if leaf_index >= 1 << HEIGHT {
            msg!("dst leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&leaf) {
            msg!("leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&prev_root) {
            msg!("prev root is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_updating_nodes_valid(&updating_nodes) {
            msg!("updating nodes are invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_commitment_valid(&commitment) {
            msg!("commitment is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        
        Ok(Self {
            receiver,
            withdraw_amount,
            nullifier_point,
            leaf_index,
            leaf,
            prev_root,
            updating_nodes,
            commitment,
        })
    }
}

impl VanillaData for WithdrawVanillaData {
    const PROOF_TYPE: ProofType = ProofType::Withdraw;
    const INPUTS_LEN: usize = 1 + 1 + 1 + 1 + 1 + 1 + 1 + HEIGHT + 4;
    const SIZE: usize = 32 + 8 + 32 * 2 + 8 + 32 + 32 + 4 + 32 * HEIGHT + 4 * 32;

    fn to_public_inputs(self) -> Box<Vec<BigInteger>> {
        let mut inputs = Box::new(Vec::with_capacity(Self::INPUTS_LEN));

        inputs.push(BigInteger::from(self.withdraw_amount));
        inputs.push(pubkey_to_fr_repr(&self.receiver));
        inputs.push(BigInteger::from(self.leaf_index));
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.push(self.nullifier_point.x);
        inputs.push(self.nullifier_point.y);
        inputs.extend(*self.updating_nodes);
        inputs.push(self.commitment.0.x);
        inputs.push(self.commitment.0.y);
        inputs.push(self.commitment.1.x);
        inputs.push(self.commitment.1.y);

        assert_eq!(inputs.len(), Self::INPUTS_LEN);

        inputs
    }
}

pub type WithdrawCredential = Credential<WithdrawVanillaData>;
