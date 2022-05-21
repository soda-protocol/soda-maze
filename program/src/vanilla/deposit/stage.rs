use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::program_error::ProgramError;

use crate::params::{bn::Fr, hasher::{get_params_bn254_x3_3, get_params_bn254_x5_4}};
use crate::{HEIGHT, hasher::poseidon::poseidon_hash_in_round};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum ProcessStage {
    HashLeaf(PoseidonHashLeaf),
    UpdateTree(PoseidonUpdateTree),
    Finished(Box<Vec<Fr>>),
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PoseidonHashLeaf {
    pub round: u8,
    pub state: Vec<Fr>,
}

impl PoseidonHashLeaf {
    pub fn new(mint: Fr, amount: Fr, commitment: Fr) -> Self {
        Self {
            round: 0,
            state: vec![Fr::zero(), mint, amount, commitment],
        }
    }

    pub fn process(mut self, friend_nodes: &[(bool, Fr)]) -> Result<ProcessStage, ProgramError> {
        let params = get_params_bn254_x5_4();
        let nr = params.full_rounds + params.partial_rounds;

        const MAX_LOOP: usize = 34;
        for _ in 0..MAX_LOOP {
            poseidon_hash_in_round(
                &params,
                self.round as usize,
                &mut self.state,
            )?;

            self.round += 1;
            if self.round >= nr {                
                return Ok(ProcessStage::UpdateTree(PoseidonUpdateTree::new(
                    self.state[0],
                    friend_nodes,
                )));
            }
        }

        Ok(ProcessStage::HashLeaf(self))
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PoseidonUpdateTree {
    pub update_nodes: Box<Vec<Fr>>,
    pub layer: u8,
    pub round: u8,
    pub state: Vec<Fr>,
}

impl PoseidonUpdateTree {
    fn new(leaf: Fr, friend_nodes: &[(bool, Fr)]) -> Self {
        let (is_left, friend) = friend_nodes[0];
        let state = if is_left {
            vec![Fr::zero(), friend, leaf]
        } else {
            vec![Fr::zero(), leaf, friend]
        };

        Self {
            update_nodes: Box::new(vec![leaf]),
            layer: 0,
            round: 0,
            state,
        }
    }

    pub fn process(mut self, friend_nodes: &[(bool, Fr)]) -> Result<ProcessStage, ProgramError> {
        let params = get_params_bn254_x3_3();
        let nr = params.full_rounds + params.partial_rounds;

        const MAX_LOOP: usize = 56;
        for _ in 0..MAX_LOOP {
            poseidon_hash_in_round(
                &params,
                self.round as usize,
                &mut self.state,
            )?;

            self.round += 1;
            if self.round >= nr {
                self.round = 0;
                self.layer += 1;
                let node_hash = self.state[0];
                self.update_nodes.push(node_hash);
    
                if self.layer as usize >= HEIGHT {
                    assert_eq!(self.update_nodes.len(), HEIGHT + 1);

                    return Ok(ProcessStage::Finished(self.update_nodes))
                } else {
                    let (is_left, friend) = friend_nodes[self.layer as usize];
                    self.state = if is_left {
                        vec![Fr::zero(), friend, node_hash]
                    } else {
                        vec![Fr::zero(), node_hash, friend]
                    };
                }
            }
        }

        Ok(ProcessStage::UpdateTree(self))
    }
}
