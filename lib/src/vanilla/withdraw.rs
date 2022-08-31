use ark_ec::{twisted_edwards_extended::{GroupProjective, GroupAffine}, TEModelParameters, ProjectiveCurve};
use ark_std::{marker::PhantomData, rc::Rc};
use anyhow::{anyhow, Result};
use ark_ff::{PrimeField, BigInteger, FpParameters};
use num_traits::Zero;

use super::{hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};
use super::commit::{self, CommitConstParams, CommitOriginInputs, CommitPrivateInputs, CommitPublicInputs};

#[derive(Default)]
pub struct WithdrawVanillaProof<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    _p: PhantomData<P>,
    _fh: PhantomData<FH>,
}

#[derive(Debug)]
pub struct WithdrawConstParams<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    pub nullifier_params: Rc<FH::Parameters>,
    pub leaf_params: Rc<FH::Parameters>,
    pub inner_params: Rc<FH::Parameters>,
    pub height: usize,
    pub commit: Option<CommitConstParams<P, FH>>,
}

#[derive(Debug)]
pub struct WithdrawOriginInputs<P: TEModelParameters> {
    pub balance: u64,
    pub withdraw_amount: u64,
    pub src_leaf_index: u64,
    pub dst_leaf_index: u64,
    pub receiver: P::BaseField,
    pub secret: P::BaseField,
    pub src_neighbor_nodes: Vec<P::BaseField>,
    pub dst_neighbor_nodes: Vec<P::BaseField>,
    pub commit: Option<CommitOriginInputs<P>>,
}

#[derive(Debug)]
pub struct WithdrawPublicInputs<P: TEModelParameters> {
    pub withdraw_amount: u64,
    pub receiver: P::BaseField,
    pub dst_leaf_index: u64,
    pub dst_leaf: P::BaseField,
    pub prev_root: P::BaseField,
    pub nullifier_point: GroupAffine<P>,
    pub update_nodes: Vec<P::BaseField>,
    pub commit: Option<CommitPublicInputs<P>>,
}

#[derive(Debug)]
pub struct WithdrawPrivateInputs<P: TEModelParameters> {
    pub balance: u64,
    pub secret: P::BaseField,
    pub src_neighbor_nodes: Vec<(bool, P::BaseField)>,
    pub dst_neighbor_nodes: Vec<(bool, P::BaseField)>,
    pub src_leaf_index: u64,
    pub src_leaf: P::BaseField,
    pub commit: Option<CommitPrivateInputs>,
}

impl<P, FH> VanillaProof<P::BaseField> for WithdrawVanillaProof<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    type ConstParams = WithdrawConstParams<P, FH>;
    type OriginInputs = WithdrawOriginInputs<P>;
    type PublicInputs = WithdrawPublicInputs<P>;
    type PrivateInputs = WithdrawPrivateInputs<P>;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let src_leaf_index = 0;
        let balance = 1;
        let receiver = P::BaseField::zero();
        let secret = P::BaseField::zero();
        let leaf = FH::hash(
            &params.leaf_params,
            &[P::BaseField::from(src_leaf_index), P::BaseField::from(balance), secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;

        let src_neighbor_nodes = vec![FH::empty_hash(); params.height];
        let mut dst_neighbor_nodes = vec![FH::empty_hash(); params.height];
        dst_neighbor_nodes[0] = leaf;

        let origin_inputs = WithdrawOriginInputs {
            balance,
            withdraw_amount: balance,
            src_leaf_index,
            dst_leaf_index: src_leaf_index + 1,
            receiver,
            secret,
            src_neighbor_nodes,
            dst_neighbor_nodes,
            commit: params.commit.as_ref().and(Some(CommitOriginInputs {
                nonce: P::ScalarField::zero(),
            })),
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &WithdrawConstParams<P, FH>,
        orig_in: &WithdrawOriginInputs<P>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.src_neighbor_nodes.len(), params.height);
        assert_eq!(orig_in.dst_neighbor_nodes.len(), params.height);
        assert!(orig_in.dst_leaf_index < (1 << params.height));
        assert!(orig_in.src_leaf_index < orig_in.dst_leaf_index);
        assert!(orig_in.withdraw_amount > 0);

        let src_neighbor_nodes = orig_in.src_neighbor_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.src_leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let dst_neighbor_nodes = orig_in.dst_neighbor_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.dst_leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let nullifier = FH::hash(
            &params.nullifier_params,
            &[P::BaseField::from(orig_in.src_leaf_index), orig_in.secret],
        ).unwrap();
        let nullifier: <P::BaseField as PrimeField>::BigInt = nullifier.into();
        let mut nullifier_bits = nullifier.to_bits_le();
        nullifier_bits.truncate(<<P::ScalarField as PrimeField>::Params as FpParameters>::CAPACITY as usize);
        let nullifier: <P::ScalarField as PrimeField>::BigInt = <<P::ScalarField as PrimeField>::BigInt as BigInteger>::from_bits_le(&nullifier_bits);
        // nullifier_point = nullifier * G
        let nullifier_point = GroupProjective::prime_subgroup_generator().mul(nullifier).into();

        let src_leaf = FH::hash(
            &params.leaf_params,
            &[P::BaseField::from(orig_in.src_leaf_index), P::BaseField::from(orig_in.balance), orig_in.secret],
        ).unwrap();
        let prev_root = gen_merkle_path::<_, FH>(&params.inner_params, &src_neighbor_nodes, src_leaf)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();
        let rest_amount = orig_in.balance.saturating_sub(orig_in.withdraw_amount);
        let dst_leaf = FH::hash(
            &params.leaf_params,
            &[P::BaseField::from(orig_in.dst_leaf_index), P::BaseField::from(rest_amount), orig_in.secret],
        ).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &dst_neighbor_nodes, dst_leaf)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let commit = params.commit
            .as_ref()
            .zip(orig_in.commit.as_ref())
            .map(|(params, jj_orig_in)| {
                commit::generate_vanilla_proof(params, jj_orig_in, orig_in.dst_leaf_index, orig_in.secret)
            })
            .transpose()?;
        let (jj_pub_in, jj_priv_in) = if let Some((pub_in, priv_in)) = commit {
            (Some(pub_in), Some(priv_in))
        } else {
            (None, None)
        };

        let pub_in = WithdrawPublicInputs {
            withdraw_amount: orig_in.withdraw_amount,
            receiver: orig_in.receiver,
            dst_leaf_index: orig_in.dst_leaf_index,
            dst_leaf,
            prev_root,
            nullifier_point,
            update_nodes,
            commit: jj_pub_in,
        };
        let priv_in = WithdrawPrivateInputs {
            balance: orig_in.balance,
            secret: orig_in.secret,
            src_neighbor_nodes,
            dst_neighbor_nodes,
            src_leaf_index: orig_in.src_leaf_index,
            src_leaf,
            commit: jj_priv_in,
        };

        Ok((pub_in, priv_in))
    }
}
