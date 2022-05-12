use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;

use super::{array::Pubkey, hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path, rabin::RabinParam};

#[derive(Default)]
pub struct DepositVanillaProof<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> {
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
}

#[derive(Clone)]
pub struct DepositOriginInputs<F: PrimeField, const HEIGHT: u8> {
    pub mint: Pubkey,
    pub amount: u64,
    pub secret: F,
    pub leaf_index: u64,
    pub friend_nodes: Vec<F>,
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
    pub leaf_index: u64,
    pub new_leaf: F,
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

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let orig_in = DepositOriginInputs {
            mint: Default::default(),
            amount: 1,
            secret: F::zero(),
            leaf_index: 0,
            friend_nodes: vec![FH::empty_hash(); HEIGHT as usize],
        };

        Self::generate_vanilla_proof(params, &orig_in)
    }

    fn generate_vanilla_proof(
        params: &DepositConstParams<F, FH>,
        orig_in: &DepositOriginInputs<F, HEIGHT>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes.len(), HEIGHT as usize);
        assert!(orig_in.leaf_index < (1 << HEIGHT));
        assert!(orig_in.amount > 0, "amount must be greater than 0");

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
            leaf_index: orig_in.leaf_index,
            new_leaf,
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
    pub nullifier_params: FH::Parameters,
    pub inner_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
    pub rabin_param: Option<RabinParam>,
}

#[derive(Clone)]
pub struct WithdrawOriginInputs<F: PrimeField, const HEIGHT: u8> {
    pub mint: Pubkey,
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
    pub mint: Pubkey,
    pub withdraw_amount: u64,
    pub nullifier: F,
    pub old_root: F,
    pub new_leaf_index: u64,
    pub new_leaf: F,
    pub update_nodes: Vec<F>,
    pub cypher: Option<Vec<F>>,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub secret_1: F,
    pub secret_2: F,
    pub friend_nodes_1: Vec<(bool, F)>,
    pub friend_nodes_2: Vec<(bool, F)>,
    pub quotient: Option<Vec<BigUint>>,
}

impl<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8> VanillaProof<F> for WithdrawVanillaProof<F, FH, HEIGHT> {
    type ConstParams = WithdrawConstParams<F, FH>;
    type OriginInputs = WithdrawOriginInputs<F, HEIGHT>;
    type PublicInputs = WithdrawPublicInputs<F>;
    type PrivateInputs = WithdrawPrivateInputs<F>;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let preimage = vec![
            Pubkey::default().to_field_element(),
            F::one(),
            F::zero(),
        ];
        let leaf = FH::hash(&params.leaf_params, &preimage)
            .map_err(|e| anyhow!("hash error: {}", e))?;

        let friend_nodes_1 = vec![FH::empty_hash(); HEIGHT as usize];
        let mut friend_nodes_2 = vec![FH::empty_hash(); HEIGHT as usize];
        friend_nodes_2[0] = leaf;

        let origin_inputs = WithdrawOriginInputs {
            mint: Pubkey::default(),
            deposit_amount: 1,
            withdraw_amount: 1,
            leaf_index_1: 0,
            leaf_index_2: 1,
            secret_1: F::zero(),
            secret_2: F::one(),
            friend_nodes_1,
            friend_nodes_2,
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &WithdrawConstParams<F, FH>,
        orig_in: &WithdrawOriginInputs<F, HEIGHT>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes_1.len(), HEIGHT as usize);
        assert_eq!(orig_in.friend_nodes_2.len(), HEIGHT as usize);
        assert!(orig_in.leaf_index_2 < (1 << HEIGHT));
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

        let nullifier = FH::hash(&params.nullifier_params, &[orig_in.secret_1])
            .map_err(|e| anyhow!("hash error: {}", e))?;

        let preimage = vec![
            orig_in.mint.to_field_element(),
            F::from(orig_in.deposit_amount),
            orig_in.secret_1,
        ];
        let leaf_1 = FH::hash(&params.leaf_params, &preimage[..]).unwrap();
        let old_root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_1, leaf_1)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let preimage = vec![
            orig_in.mint.to_field_element(),
            F::from(orig_in.deposit_amount - orig_in.withdraw_amount),
            orig_in.secret_2,
        ];
        let leaf_2 = FH::hash(&params.leaf_params, &preimage[..]).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_2, leaf_2.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let (quotient, cypher) = if let Some(param) = &params.rabin_param {
            let preimage = param.gen_preimage(leaf_1);
            let (quotient, cypher) = (&preimage * &preimage).div_rem(&param.modulus);
            let quotient = param.gen_quotient_array(quotient);
            let cypher = param.gen_cypher_array(cypher);
            
            (Some(quotient), Some(cypher))
        } else {
            (None, None)
        };

        let pub_in = WithdrawPublicInputs {
            mint: orig_in.mint,
            withdraw_amount: orig_in.withdraw_amount,
            new_leaf_index: orig_in.leaf_index_2,
            nullifier,
            old_root,
            new_leaf: leaf_2,
            update_nodes,
            cypher,
        };
        let priv_in = WithdrawPrivateInputs {
            deposit_amount: orig_in.deposit_amount,
            secret_1: orig_in.secret_1,
            secret_2: orig_in.secret_2,
            friend_nodes_1,
            friend_nodes_2,
            quotient,
        };

        Ok((pub_in, priv_in))
    }
}
