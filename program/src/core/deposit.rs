use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{msg, entrypoint::ProgramResult};

use crate::params::{bn::Fr, rabin::RABIN_MODULUS_LEN, proof::ProofType, HEIGHT};
use crate::{error::MazeError, bn::BigInteger256 as BigInteger};

use super::{commitment::is_commitment_valid, node::is_updating_nodes_valid};
use super::{VanillaData, credential::Credential};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositVanillaData {
    pub deposit_amount: u64,
    pub leaf_index: u64,
    pub leaf: Fr,
    pub prev_root: Fr,
    pub updating_nodes: Box<Vec<Fr>>,
    pub commitment: Option<Box<Vec<Fr>>>,
}

impl DepositVanillaData {
    pub fn new(
        deposit_amount: u64,
        leaf_index: u64,
        leaf: Fr,
        prev_root: Fr,
        updating_nodes: Box<Vec<Fr>>,
    ) -> Self {
        Self {
            deposit_amount,
            leaf_index,
            leaf,
            prev_root,
            updating_nodes,
            commitment: None,
        }
    }

    // In principle there's no need to create this function,
    // but solana transaction size is restrict to less than 1280 bytes,
    // so commitment must filled in another transaction
    pub fn fill_commitment(&mut self, commitment: Box<Vec<Fr>>) -> ProgramResult {
        if self.commitment.is_none() {
            self.commitment = Some(commitment);
            Ok(())
        } else {
            msg!("commitment is already filled");
            Err(MazeError::InvalidVanillaData.into())
        }
    }
}

impl VanillaData for DepositVanillaData {
    const PROOF_TYPE: ProofType = ProofType::Deposit;
    const SIZE: usize = 8 + 8 + 32 + 32 + 4 + HEIGHT * 32 + 1 + 4 + RABIN_MODULUS_LEN * 32;

    fn check_valid(&self) -> ProgramResult {
        if self.leaf_index >= 1 << HEIGHT {
            msg!("leaf index is too large");
            return Err(MazeError::InvalidVanillaData.into());
        }
        if !self.leaf.is_valid() {
            msg!("leaf is invalid");
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
        if let Some(commitment) = self.commitment.as_ref() {
            if !is_commitment_valid(commitment) {
                msg!("commitment is invalid");
                return Err(MazeError::InvalidVanillaData.into());
            }
        }

        Ok(())
    }

    fn to_public_inputs(self) -> Box<Vec<Fr>> {
        let mut inputs = Box::new(Vec::with_capacity(Self::INPUTS_LEN));

        inputs.push(Fr::from_repr(BigInteger::from(self.deposit_amount)).unwrap());
        inputs.push(Fr::from_repr(BigInteger::from(self.leaf_index)).unwrap());
        inputs.push(self.leaf);
        inputs.push(self.prev_root);
        inputs.extend_from_slice(&self.updating_nodes);
        if let Some(commitment) = self.commitment {
            inputs.extend_from_slice(&commitment);
        }

        assert_eq!(inputs.len(), Self::INPUTS_LEN);

        inputs
    }
}

pub type DepositCredential = Credential<DepositVanillaData>;
