use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, program_error::ProgramError};

use crate::params::{verify::ProofType, HEIGHT};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger};

use super::is_fr_valid;
use super::node::is_updating_nodes_valid;
use super::commitment::{is_commitment_valid, InnerCommitment};
use super::{VanillaData, credential::Credential};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositVanillaData {
    pub deposit_amount: u64,
    pub leaf_index: u64,
    pub leaf: BigInteger,
    pub prev_root: BigInteger,
    pub updating_nodes: Box<Vec<BigInteger>>,
    pub commitment: InnerCommitment,
}

impl DepositVanillaData {
    pub fn new(
        deposit_amount: u64,
        leaf_index: u64,
        leaf: BigInteger,
        prev_root: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
        commitment: InnerCommitment,
    ) -> Result<Self, ProgramError> {
        if leaf_index >= 1 << HEIGHT {
            msg!("leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&leaf) {
            msg!("leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&prev_root) {
            msg!("prev_root is invalid");
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
            deposit_amount,
            leaf_index,
            leaf,
            prev_root,
            updating_nodes,
            commitment,
        })
    }
}

impl VanillaData for DepositVanillaData {
    const PROOF_TYPE: ProofType = ProofType::Deposit;
    const INPUTS_LEN: usize = 1 + 1 + 1 + 1 + HEIGHT + 4;
    const SIZE: usize = 8 + 8 + 32 + 32 + 4 + HEIGHT * 32 + 4 * 32;

    fn to_public_inputs(self) -> Box<Vec<BigInteger>> {
        let mut inputs = Box::new(Vec::with_capacity(Self::INPUTS_LEN));

        inputs.push(BigInteger::from(self.deposit_amount));
        inputs.push(BigInteger::from(self.leaf_index));
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.extend_from_slice(&self.updating_nodes);
        inputs.push(self.commitment.0.x);
        inputs.push(self.commitment.0.y);
        inputs.push(self.commitment.1.x);
        inputs.push(self.commitment.1.y);

        assert_eq!(inputs.len(), Self::INPUTS_LEN);

        inputs
    }
}

pub type DepositCredential = Credential<DepositVanillaData>;
