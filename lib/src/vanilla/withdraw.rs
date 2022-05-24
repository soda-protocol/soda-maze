use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;

use super::{hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};

#[derive(Default)]
pub struct WithdrawVanillaProof<F: PrimeField, FH: FieldHasher<F>> {
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
}

pub struct WithdrawConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub nullifier_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
    pub inner_params: FH::Parameters,
    pub height: usize,
}

#[derive(Clone)]
pub struct WithdrawOriginInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub withdraw_amount: u64,
    pub src_leaf_index: u64,
    pub dst_leaf_index: u64,
    pub secret: F,
    pub src_friend_nodes: Vec<F>,
    pub dst_friend_nodes: Vec<F>,
}

#[derive(Clone)]
pub struct WithdrawPublicInputs<F: PrimeField> {
    pub withdraw_amount: u64,
    pub nullifier: F,
    pub prev_root: F,
    pub dst_leaf_index: u64,
    pub dst_leaf: F,
    pub update_nodes: Vec<F>,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub secret: F,
    pub src_friend_nodes: Vec<(bool, F)>,
    pub dst_friend_nodes: Vec<(bool, F)>,
    pub src_leaf_index: u64,
    pub src_leaf: F,
}

impl<F, FH> VanillaProof<F> for WithdrawVanillaProof<F, FH>
where
    F: PrimeField,
    FH: FieldHasher<F>,
{
    type ConstParams = WithdrawConstParams<F, FH>;
    type OriginInputs = WithdrawOriginInputs<F>;
    type PublicInputs = WithdrawPublicInputs<F>;
    type PrivateInputs = WithdrawPrivateInputs<F>;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let src_leaf_index = 0;
        let deposit_amount = 1;
        let secret = F::zero();
        let leaf = FH::hash(
            &params.leaf_params,
            &[F::from(src_leaf_index), F::from(deposit_amount), secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;

        let src_friend_nodes = vec![FH::empty_hash(); params.height];
        let mut dst_friend_nodes = vec![FH::empty_hash(); params.height];
        dst_friend_nodes[0] = leaf;

        let origin_inputs = WithdrawOriginInputs {
            deposit_amount,
            withdraw_amount: deposit_amount,
            src_leaf_index,
            dst_leaf_index: src_leaf_index + 1,
            secret,
            src_friend_nodes,
            dst_friend_nodes,
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &WithdrawConstParams<F, FH>,
        orig_in: &WithdrawOriginInputs<F>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.src_friend_nodes.len(), params.height);
        assert_eq!(orig_in.dst_friend_nodes.len(), params.height);
        assert!(orig_in.dst_leaf_index < (1 << params.height));
        assert!(orig_in.src_leaf_index < orig_in.dst_leaf_index);
        assert!(orig_in.withdraw_amount > 0);
        assert!(orig_in.deposit_amount >= orig_in.withdraw_amount);

        let src_friend_nodes = orig_in.src_friend_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.src_leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let dst_friend_nodes = orig_in.dst_friend_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.dst_leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let src_leaf = FH::hash(
            &params.leaf_params,
            &[F::from(orig_in.src_leaf_index), F::from(orig_in.deposit_amount), orig_in.secret],
        ).unwrap();
        let prev_root = gen_merkle_path::<_, FH>(&params.inner_params, &src_friend_nodes, src_leaf)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();
        let rest_amount = orig_in.deposit_amount - orig_in.withdraw_amount;
        let dst_leaf = FH::hash(&params.leaf_params, &[F::from(rest_amount), orig_in.secret]).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &dst_friend_nodes, dst_leaf)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let pub_in = WithdrawPublicInputs {
            withdraw_amount: orig_in.withdraw_amount,
            nullifier: orig_in.secret,
            prev_root,
            dst_leaf_index: orig_in.dst_leaf_index,
            dst_leaf,
            update_nodes,
        };
        let priv_in = WithdrawPrivateInputs {
            deposit_amount: orig_in.deposit_amount,
            secret: orig_in.secret,
            src_friend_nodes,
            dst_friend_nodes,
            src_leaf_index: orig_in.src_leaf_index,
            src_leaf,
        };

        Ok((pub_in, priv_in))
    }
}
