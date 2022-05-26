use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, entrypoint::ProgramResult};

use crate::params::{bn::Fr, proof::ProofType, HEIGHT};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger};
use super::{VanillaData, credential::Credential, node::is_updating_nodes_valid};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct WithdrawVanillaData {
    pub withdraw_amount: u64,
    pub nullifier: Fr,
    pub leaf_index: u64,
    pub leaf: Fr,
    pub prev_root: Fr,
    pub updating_nodes: Box<Vec<Fr>>,
}

impl WithdrawVanillaData {
    pub fn new(
        withdraw_amount: u64,
        nullifier: Fr,
        leaf_index: u64,
        leaf: Fr,
        prev_root: Fr,
        updating_nodes: Box<Vec<Fr>>,
    ) -> Self {
        Self {
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
    const SIZE: usize = 8 + 32 + 8 + 32 + 32 + 4 + 32 * HEIGHT;

    fn check_valid(&self) -> ProgramResult {
        if !self.nullifier.is_valid() {
            msg!("nullifier is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if self.leaf_index >= 1 << HEIGHT {
            msg!("dst leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.leaf.is_valid() {
            msg!("dst leaf is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.prev_root.is_valid() {
            msg!("prev root is invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !is_updating_nodes_valid(&self.updating_nodes) {
            msg!("updating nodes are invalid");
            return Err(MazeError::InvalidVanillaData.into());
        }

        Ok(())
    }

    fn to_public_inputs(self) -> Box<Vec<Fr>> {
        let mut inputs = Box::new(Vec::with_capacity(Self::INPUTS_LEN));

        inputs.push(Fr::from_repr(BigInteger::from(self.withdraw_amount)).unwrap());
        inputs.push(self.nullifier);
        inputs.push(Fr::from_repr(BigInteger::from(self.leaf_index)).unwrap());
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.extend(*self.updating_nodes);

        assert_eq!(inputs.len(), Self::INPUTS_LEN);

        inputs
    }
}

pub type WithdrawCredential = Credential<WithdrawVanillaData>;
