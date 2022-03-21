use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;

use super::{array::Pubkey, hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};

#[derive(Default)]
pub struct DepositVanillaProof<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> {
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
}

#[derive(Clone)]
pub struct DepositOriginInputs<F: PrimeField, const HEIGHT: u8> {
    pub friend_nodes: Vec<F>,
    pub leaf_index: u64,
    pub mint: Pubkey,
    pub amount: u64,
    pub secret: F,
}

impl<F: PrimeField, const HEIGHT: u8> Default for DepositOriginInputs<F, HEIGHT> {
    fn default() -> Self {
        Self {
            friend_nodes: vec![F::zero(); HEIGHT as usize],
            leaf_index: 0,
            mint: Default::default(),
            amount: 0,
            secret: F::zero(),
        }
    }
}

pub struct DepositConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub inner_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
}

#[derive(Clone)]
pub struct DepositPublicInputs<F: PrimeField> {
    pub mint: Pubkey,
    pub amount: u64,
    pub old_root: F,
    pub new_leaf: F,
    pub leaf_index: u64,
    pub update_nodes: Vec<F>,
}

#[derive(Clone)]
pub struct DepositPrivateInputs<F: PrimeField> {
    pub secret: F,
    pub friend_nodes: Vec<(bool, F)>,
}

impl<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> VanillaProof<F> for DepositVanillaProof<F, FH, HEIGHT> {
    type ConstParams = DepositConstParams<F, FH>;
    type OriginInputs = DepositOriginInputs<F, HEIGHT>;
    type PublicInputs = DepositPublicInputs<F>;
    type PrivateInputs = DepositPrivateInputs<F>;

    fn generate_vanilla_proof(
        params: &DepositConstParams<F, FH>,
        orig_in: &DepositOriginInputs<F, HEIGHT>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes.len(), HEIGHT as usize);
        assert!(orig_in.leaf_index < (1 << HEIGHT));

        let friend_nodes = orig_in.friend_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let old_root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes, FH::empty_hash())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let preimage = vec![
            orig_in.mint.to_field_element(),
            F::from(orig_in.amount),
            orig_in.secret,
        ];
        let new_leaf = FH::hash(&params.leaf_params, &preimage[..]).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes, new_leaf.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let pub_in = DepositPublicInputs {
            mint: orig_in.mint,
            amount: orig_in.amount,
            old_root,
            new_leaf,
            leaf_index: orig_in.leaf_index,
            update_nodes,
        };
        let priv_in = DepositPrivateInputs {
            secret: orig_in.secret,
            friend_nodes,
        };

        Ok((pub_in, priv_in))
    }
}

#[derive(Default)]
pub struct WithdrawVanillaProof<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> {
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
}

pub struct WithdrawConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub inner_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
    pub nullifier_params: FH::Parameters,
}

#[derive(Clone)]
pub struct WithdrawOriginInputs<F: PrimeField, const HEIGHT: u8> {
    pub friend_nodes: Vec<F>,
    pub leaf_index: u64,
    pub mint: Pubkey,
    pub deposit_amount: u64,
    pub withdraw_amount: u64,
    pub secret: F,
}

impl<F: PrimeField, const HEIGHT: u8> Default for WithdrawOriginInputs<F, HEIGHT> {
    fn default() -> Self {
        Self {
            friend_nodes: vec![F::zero(); HEIGHT as usize],
            leaf_index: 0,
            mint: Default::default(),
            deposit_amount: 0,
            withdraw_amount: 0,
            secret: F::zero(),
        }
    }
}

#[derive(Clone)]
pub struct WithdrawPublicInputs<F: PrimeField> {
    pub mint: Pubkey,
    pub withdraw_amount: u64,
    pub root: F,
    pub nullifier: F,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub secret: F,
    pub friend_nodes: Vec<(bool, F)>,
}

impl<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> VanillaProof<F> for WithdrawVanillaProof<F, FH, HEIGHT> {
    type ConstParams = WithdrawConstParams<F, FH>;
    type OriginInputs = WithdrawOriginInputs<F, HEIGHT>;
    type PublicInputs = WithdrawPublicInputs<F>;
    type PrivateInputs = WithdrawPrivateInputs<F>;

    fn generate_vanilla_proof(
        params: &WithdrawConstParams<F, FH>,
        orig_in: &WithdrawOriginInputs<F, HEIGHT>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes.len(), HEIGHT as usize);
        assert!(orig_in.leaf_index < (1 << HEIGHT));

        let friend_nodes = orig_in.friend_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let nullifier = FH::hash(&params.nullifier_params, &[orig_in.secret]).unwrap();
        let preimage = vec![orig_in.mint.to_field_element(), F::from(orig_in.deposit_amount), orig_in.secret];
        let leaf = FH::hash(&params.leaf_params, &preimage[..]).unwrap();
        let root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes, leaf.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let pub_in = WithdrawPublicInputs {
            mint: orig_in.mint,
            withdraw_amount: orig_in.withdraw_amount,
            root,
            nullifier,
        };
        let priv_in = WithdrawPrivateInputs {
            deposit_amount: orig_in.deposit_amount,
            secret: orig_in.secret,
            friend_nodes,
        };

        Ok((pub_in, priv_in))
    }
}