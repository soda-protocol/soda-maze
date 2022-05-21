use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;

use super::{hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};

#[derive(Default)]
pub struct WithdrawVanillaProof<F: PrimeField, FH: FieldHasher<F>> {
    _f: PhantomData<F>,
    _fh1: PhantomData<FH>,
}

pub struct WithdrawConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub commitment_params: FH::Parameters,
    pub nullifier_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
    pub inner_params: FH::Parameters,
    pub height: usize,
}

#[derive(Clone)]
pub struct WithdrawOriginInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub withdraw_amount: u64,
    pub leaf_index_1: u64,
    pub leaf_index_2: u64,
    pub secret_1: F,
    pub secret_2: F,
    pub friend_nodes_1: Vec<F>,
    pub friend_nodes_2: Vec<F>,
}

#[derive(Clone)]
pub struct WithdrawPublicInputs<F: PrimeField> {
    pub withdraw_amount: u64,
    pub nullifier: F,
    pub old_root: F,
    pub new_leaf_index: u64,
    pub new_leaf: F,
    pub update_nodes: Vec<F>,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub secret_1: F,
    pub secret_2: F,
    pub friend_nodes_1: Vec<(bool, F)>,
    pub friend_nodes_2: Vec<(bool, F)>,
    pub old_leaf_index: u64,
    pub old_leaf: F,
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
        let secret = F::zero();
        let commitment = FH::hash(&params.commitment_params, &[secret])
            .map_err(|e| anyhow!("hash error: {}", e))?;
        let leaf = FH::hash(&params.leaf_params, &[F::one(), commitment])
            .map_err(|e| anyhow!("hash error: {}", e))?;

        let friend_nodes_1 = vec![FH::empty_hash(); params.height];
        let mut friend_nodes_2 = vec![FH::empty_hash(); params.height];
        friend_nodes_2[0] = leaf;

        let origin_inputs = WithdrawOriginInputs {
            deposit_amount: 1,
            withdraw_amount: 1,
            leaf_index_1: 0,
            leaf_index_2: 1,
            secret_1: F::zero(),
            secret_2: F::zero(),
            friend_nodes_1,
            friend_nodes_2,
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &WithdrawConstParams<F, FH>,
        orig_in: &WithdrawOriginInputs<F>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes_1.len(), params.height);
        assert_eq!(orig_in.friend_nodes_2.len(), params.height);
        assert!(orig_in.leaf_index_2 < (1 << params.height));
        assert!(orig_in.leaf_index_1 < orig_in.leaf_index_2, "leaf_index_1 must be less than leaf_index_2");
        assert!(orig_in.withdraw_amount > 0, "withdraw amount must be greater than 0");
        assert!(orig_in.deposit_amount >= orig_in.withdraw_amount, "deposit amount must be greater or equal than withdraw amount");

        let friend_nodes_1 = orig_in.friend_nodes_1
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index_1 >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let friend_nodes_2 = orig_in.friend_nodes_2
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index_2 >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let commitment = FH::hash(&params.commitment_params, &[orig_in.secret_1])
            .map_err(|e| anyhow!("hash error: {}", e))?;
        let nullifier = FH::hash(&params.nullifier_params, &[F::from(orig_in.leaf_index_1), orig_in.secret_1])
            .map_err(|e| anyhow!("hash error: {}", e))?;
        let leaf_1 = FH::hash(&params.leaf_params, &[F::from(orig_in.deposit_amount), commitment]).unwrap();
        let old_root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_1, leaf_1)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();
        let rest_amount = orig_in.deposit_amount - orig_in.withdraw_amount;
        let commitment = FH::hash(&params.commitment_params, &[orig_in.secret_2])
            .map_err(|e| anyhow!("hash error: {}", e))?;
        let leaf_2 = FH::hash(&params.leaf_params, &[F::from(rest_amount), commitment]).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_2, leaf_2)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let pub_in = WithdrawPublicInputs {
            withdraw_amount: orig_in.withdraw_amount,
            new_leaf_index: orig_in.leaf_index_2,
            nullifier,
            old_root,
            new_leaf: leaf_2,
            update_nodes,
        };
        let priv_in = WithdrawPrivateInputs {
            deposit_amount: orig_in.deposit_amount,
            secret_1: orig_in.secret_1,
            secret_2: orig_in.secret_2,
            friend_nodes_1,
            friend_nodes_2,
            old_leaf_index: orig_in.leaf_index_1,
            old_leaf: leaf_1,
        };

        Ok((pub_in, priv_in))
    }
}
