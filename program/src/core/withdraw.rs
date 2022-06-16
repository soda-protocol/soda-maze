use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, pubkey::Pubkey, entrypoint::ProgramResult};

use crate::params::{verify::ProofType, HEIGHT};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger};
use super::{is_fr_valid, VanillaData, credential::Credential, node::is_updating_nodes_valid};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawVanillaData {
    pub delegator: Pubkey,
    pub withdraw_amount: u64,
    pub nullifier: BigInteger,
    pub leaf_index: u64,
    pub leaf: BigInteger,
    pub prev_root: BigInteger,
    pub updating_nodes: Box<Vec<BigInteger>>,
}

impl WithdrawVanillaData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delegator: Pubkey,
        withdraw_amount: u64,
        nullifier: BigInteger,
        leaf_index: u64,
        leaf: BigInteger,
        prev_root: BigInteger,
        updating_nodes: Box<Vec<BigInteger>>,
    ) -> Self {
        Self {
            delegator,
            withdraw_amount,
            nullifier,
            leaf_index,
            leaf,
            prev_root,
            updating_nodes,
        }
    }
}

impl VanillaData for WithdrawVanillaData {
    const PROOF_TYPE: ProofType = ProofType::Withdraw;
    const SIZE: usize = 32 + 8 + 32 + 8 + 32 + 32 + 4 + 32 * HEIGHT;

    fn check_valid(&self) -> ProgramResult {
        if !is_fr_valid(&self.nullifier) {
            msg!("nullifier is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if self.leaf_index >= 1 << HEIGHT {
            msg!("dst leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&self.leaf) {
            msg!("leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_fr_valid(&self.prev_root) {
            msg!("prev root is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_updating_nodes_valid(&self.updating_nodes) {
            msg!("updating nodes are invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }

        Ok(())
    }

    fn to_public_inputs(self) -> Box<Vec<BigInteger>> {
        let mut inputs = Box::new(Vec::with_capacity(Self::INPUTS_LEN));

        inputs.push(BigInteger::from(self.withdraw_amount));
        inputs.push(self.nullifier);
        inputs.push(BigInteger::from(self.leaf_index));
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.extend(*self.updating_nodes);

        assert_eq!(inputs.len(), Self::INPUTS_LEN);

        inputs
    }
}

pub type WithdrawCredential = Credential<WithdrawVanillaData>;
