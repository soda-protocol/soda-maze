use ark_std::{marker::PhantomData, rc::Rc};
use anyhow::{anyhow, Result};
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use num_traits::Zero;

use super::{hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};
use super::commit::{self, CommitConstParams, CommitOriginInputs, CommitPrivateInputs, CommitPublicInputs};

#[derive(Default)]
pub struct DepositVanillaProof<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    _p: PhantomData<P>,
    _fh: PhantomData<FH>,
}

#[derive(Debug)]
pub struct DepositConstParams<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    pub leaf_params: Rc<FH::Parameters>,
    pub inner_params: Rc<FH::Parameters>,
    pub height: usize,
    pub commit: Option<CommitConstParams<P, FH>>,
}

#[derive(Debug)]
pub struct DepositOriginInputs<P: TEModelParameters> {
    pub leaf_index: u64,
    pub deposit_amount: u64,
    pub secret: P::BaseField,
    pub neighbor_nodes: Vec<P::BaseField>,
    pub commit: Option<CommitOriginInputs<P>>,
}

#[derive(Debug)]
pub struct DepositPublicInputs<P: TEModelParameters> {
    pub deposit_amount: u64,
    pub leaf_index: u64,
    pub leaf: P::BaseField,
    pub prev_root: P::BaseField,
    pub update_nodes: Vec<P::BaseField>,
    pub commit: Option<CommitPublicInputs<P>>,
}

#[derive(Debug)]
pub struct DepositPrivateInputs<P: TEModelParameters> {
    pub secret: P::BaseField,
    pub neighbor_nodes: Vec<(bool, P::BaseField)>,
    pub commit: Option<CommitPrivateInputs>,
}

impl<P, FH> VanillaProof<P::BaseField> for DepositVanillaProof<P, FH>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    P::BaseField: PrimeField,
{
    type ConstParams = DepositConstParams<P, FH>;
    type OriginInputs = DepositOriginInputs<P>;
    type PublicInputs = DepositPublicInputs<P>;
    type PrivateInputs = DepositPrivateInputs<P>;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let origin_inputs = DepositOriginInputs {
            leaf_index: 0,
            deposit_amount: 1,
            secret: P::BaseField::zero(),
            neighbor_nodes: vec![FH::empty_hash(); params.height],
            commit: params.commit.as_ref().and(Some(CommitOriginInputs {
                nonce: P::ScalarField::zero(),
            })),
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &DepositConstParams<P, FH>,
        orig_in: &DepositOriginInputs<P>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.neighbor_nodes.len(), params.height);
        assert!(orig_in.leaf_index < (1 << params.height));
        assert!(orig_in.deposit_amount > 0, "deposit amount must be greater than 0");

        let neighbor_nodes = orig_in.neighbor_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let leaf = FH::hash(&params.leaf_params, &[
            P::BaseField::from(orig_in.leaf_index),
            P::BaseField::from(orig_in.deposit_amount),
            orig_in.secret,
        ]).map_err(|e| anyhow!("hash error: {}", e))?;

        let prev_root = gen_merkle_path::<_, FH>(
            &params.inner_params,
            &neighbor_nodes,
            FH::empty_hash(),
        )
        .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
        .last()
        .unwrap()
        .clone();
        let update_nodes = gen_merkle_path::<_, FH>(
            &params.inner_params,
            &neighbor_nodes,
            leaf,
        ).map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let commit = params.commit
            .as_ref()
            .zip(orig_in.commit.as_ref())
            .map(|(params, jj_orig_in)| {
                commit::generate_vanilla_proof(params, jj_orig_in, orig_in.leaf_index, orig_in.secret)
            })
            .transpose()?;
        let (jj_pub_in, jj_priv_in) =
            if let Some((pub_in, priv_in)) = commit {
                (Some(pub_in), Some(priv_in))
            } else {
                (None, None)
            };

        let pub_in = DepositPublicInputs {
            deposit_amount: orig_in.deposit_amount,
            leaf_index: orig_in.leaf_index,
            leaf,
            prev_root,
            update_nodes,
            commit: jj_pub_in,
        };
        let priv_in = DepositPrivateInputs {
            secret: orig_in.secret,
            neighbor_nodes,
            commit: jj_priv_in,
        };

        Ok((pub_in, priv_in))
    }
}
