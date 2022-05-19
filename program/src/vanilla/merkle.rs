use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;
use solana_program::entrypoint::ProgramResult;

use crate::params::{bn::Fr, hasher::{get_params_bn254_x3_3, get_params_bn254_x5_4}};
use crate::{HEIGHT, hasher::poseidon::poseidon_hash_in_round};

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PoseidonMerkleHasher {
    pub friend_nodes: Box<Vec<(bool, Fr)>>,
    pub updating_nodes: Box<Vec<Fr>>,
    pub layer: u8,
    pub round: u8,
    pub state: Vec<Fr>,
}

impl PoseidonMerkleHasher {
    pub fn new(leaf: Fr, friend_nodes: Box<Vec<(bool, Fr)>>) -> Self {
        assert_eq!(friend_nodes.len(), HEIGHT);

        let (is_left, friend) = friend_nodes[0];
        let state = if is_left {
            vec![Fr::zero(), friend, leaf]
        } else {
            vec![Fr::zero(), leaf, friend]
        };

        PoseidonMerkleHasher {
            friend_nodes,
            updating_nodes: Box::new(Vec::new()),
            layer: 0,
            round: 0,
            state,
        }
    }

    pub fn process(&mut self) -> ProgramResult {
        if self.updating_nodes.len() >= HEIGHT {
            return Ok(());
        }

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
                self.updating_nodes.push(node_hash);
                if self.layer as usize >= HEIGHT {
                    assert_eq!(self.updating_nodes.len(), HEIGHT);
                    self.state = Vec::new();
                    break;
                } else {
                    let (is_left, friend) = self.friend_nodes[self.layer as usize];
                    self.state = if is_left {
                        vec![Fr::zero(), friend, node_hash]
                    } else {
                        vec![Fr::zero(), node_hash, friend]
                    };
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct LeafHasher {
    pub round: u8,
    pub state: Vec<Fr>,
    pub leaf: Option<Fr>,
}

impl LeafHasher {
    pub fn new(mint: Fr, amount: Fr, commitment: Fr) -> Self {
        Self {
            round: 0,
            state: vec![Fr::zero(), mint, amount, commitment],
            leaf: None,
        }
    }

    pub fn process(&mut self) -> ProgramResult {
        if self.leaf.is_some() {
            return Ok(());
        }

        let params = get_params_bn254_x5_4();
        let nr = params.full_rounds + params.partial_rounds;

        const MAX_LOOP: usize = 32;
        for _ in 0..MAX_LOOP {
            poseidon_hash_in_round(
                &params,
                self.round as usize,
                &mut self.state,
            )?;

            self.round += 1;
            if self.round >= nr {
                self.leaf = Some(self.state[0]);
                self.state = Vec::new();
                break;
            }
        }

        Ok(())
    }
}
