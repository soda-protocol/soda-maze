use anyhow::{anyhow, Error};
use ark_std::{marker::PhantomData, collections::btree_map::BTreeMap};
use ark_ff::PrimeField;

use crate::primitives::{merkle::gen_merkle_path, array::Pubkey, hasher::FieldHasher};
use crate::circuits::{Deposit, Withdrawal, hasher::FieldHasherGadget};

pub type MerkleIndex = (u8, u64);
pub type UpdateNodes<F> = Vec<F>;

pub struct MazeContext<F, FH, FHG, const HEIGHT: u8>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    leaf_params: FH::Parameters,
    inner_params: FH::Parameters,
    node_map: BTreeMap<MerkleIndex, F>,
    _p: PhantomData<FHG>,
}

impl<F, FH, FHG, const HEIGHT: u8> MazeContext<F, FH, FHG, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,  
{
    pub fn gen_deposit_circuit(
        self,
        leaf_index: u64,
        mint: Pubkey,
        amount: u64,
        secret: F,
    ) -> Result<(Deposit<F, FH, FHG, HEIGHT>, UpdateNodes<F>), Error> {
        let ref node_map = self.node_map;
        let friend_nodes = (0..HEIGHT)
            .into_iter()
            .map(|layer| {
                let is_left = ((leaf_index >> layer) & 1) == 1;
                let index = if is_left { leaf_index - 1 } else { leaf_index + 1 };
                let node = node_map
                    .get(&(layer, index))
                    .ok_or(anyhow!("missing node, layer {}, index {}", layer, index))?;

                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let old_root = gen_merkle_path::<_, FH, HEIGHT>(&self.inner_params, &friend_nodes, FH::empty_hash())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let preimage = vec![mint.to_field_element(), F::from(amount), secret];
        let new_leaf = FH::hash(&self.leaf_params, &preimage[..]).unwrap();
        let update_nodes = gen_merkle_path::<_, FH, HEIGHT>(&self.inner_params, &friend_nodes, new_leaf.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let deposit = Deposit::new(
            mint,
            amount,
            secret,
            self.leaf_params,
            leaf_index,
            old_root,
            new_leaf,
            friend_nodes,
            update_nodes.clone(),
            self.inner_params,
        );

        Ok((deposit, update_nodes))
    }

    pub fn gen_withdraw_circuit(
        self,
        leaf_index: u64,
        mint: Pubkey,
        deposit_amount: u64,
        withdraw_amount: u64,
        secret: F,
    ) -> Result<Withdrawal<F, FH, FHG, HEIGHT>, Error> {
        let ref node_map = self.node_map;
        let friend_nodes = (0..HEIGHT)
            .into_iter()
            .map(|layer| {
                let is_left = ((leaf_index >> layer) & 1) == 1;
                let index = if is_left { leaf_index - 1 } else { leaf_index + 1 };
                let node = node_map
                    .get(&(layer, index))
                    .ok_or(anyhow!("missing node, layer {}, index {}", layer, index))?;

                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let nullifier = FH::hash(&self.leaf_params, &[secret]).unwrap();
        let preimage = vec![mint.to_field_element(), F::from(deposit_amount), secret];
        let leaf = FH::hash(&self.leaf_params, &preimage[..]).unwrap();
        let root = gen_merkle_path::<_, FH, HEIGHT>(&self.inner_params, &friend_nodes, leaf.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let withdrawal = Withdrawal::new(
            mint,
            withdraw_amount,
            deposit_amount,
            secret,
            nullifier,
            self.leaf_params,
            root,
            friend_nodes,
            self.inner_params,
        );

        Ok(withdrawal)
    }
}