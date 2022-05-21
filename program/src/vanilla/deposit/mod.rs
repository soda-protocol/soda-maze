mod stage;
mod processor;

use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::IsInitialized;
use solana_program::pubkey::Pubkey;
use stage::{ProcessStage, PoseidonHashLeaf};

use crate::Packer;
use crate::gadget::pubkey_to_fr;
use crate::{params::bn::Fr, HEIGHT};
use crate::bn::BigInteger256 as BigInteger;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DepositInfo {
    pub is_initialized: bool,
    pub pool: Pubkey,
    pub owner: Pubkey,
    pub leaf_index: u64,
    pub mint: Pubkey,
    pub deposit_amount: u64,
    pub stage: ProcessStage,
}

impl IsInitialized for DepositInfo {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Packer for DepositInfo {
    const LEN: usize = 1088;
}

impl DepositInfo {
    pub fn new(
        pool: Pubkey,
        owner: Pubkey,
        leaf_index: u64,
        mint: Pubkey,
        deposit_amount: u64,
        commitment: Fr,
    ) -> Self {
        Self {
            is_initialized: true,
            pool,
            owner,
            leaf_index,
            mint,
            deposit_amount,
            stage: ProcessStage::HashLeaf(PoseidonHashLeaf::new(
                pubkey_to_fr(mint),
                Fr::from_repr(BigInteger::from(deposit_amount)).unwrap(),
                commitment,
            )),
        }
    }

    pub fn process(
        mut self,
        friend_nodes: &[(bool, Fr)],
    ) -> Result<Self, ProgramError> {
        assert_eq!(friend_nodes.len(), HEIGHT);

        let stage = match self.stage {
            ProcessStage::HashLeaf(hash_leaf) => {
                hash_leaf.process(friend_nodes)?
            }
            ProcessStage::UpdateTree(update_tree) => {
                update_tree.process(friend_nodes)?
            }
            ProcessStage::Finished(update_nodes) => {
                ProcessStage::Finished(update_nodes)
            }
        };

        Ok(Self {
            stage,
            ..self
        })
    }
}