use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::{PrimeField, FpParameters};
use num_bigint::BigUint;
use num_integer::Integer;

use super::{array::Pubkey, hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path, rabin::RabinParam};

#[derive(Default)]
pub struct WithdrawVanillaProof<F: PrimeField, FH: FieldHasher<F>> {
    _f: PhantomData<F>,
    _fh1: PhantomData<FH>,
}

pub struct WithdrawConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub secret_params: FH::Parameters,
    pub nullifier_params: FH::Parameters,
    pub leaf_params: FH::Parameters,
    pub inner_params: FH::Parameters,
    pub height: usize,
    pub rabin_param: Option<RabinParam>,
}

#[derive(Clone)]
pub struct WithdrawOriginInputs<F: PrimeField> {
    pub mint: Pubkey,
    pub deposit_amount: u64,
    pub withdraw_amount: u64,
    pub leaf_index_1: u64,
    pub leaf_index_2: u64,
    pub secret: F,
    pub friend_nodes_1: Vec<F>,
    pub friend_nodes_2: Vec<F>,
    pub random_padding: Option<Vec<BigUint>>,
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
    pub cipher: Option<Vec<F>>,
}

#[derive(Clone)]
pub struct WithdrawPrivateInputs<F: PrimeField> {
    pub deposit_amount: u64,
    pub secret: F,
    pub friend_nodes_1: Vec<(bool, F)>,
    pub friend_nodes_2: Vec<(bool, F)>,
    pub old_leaf_index: u64,
    pub old_leaf: F,
    pub quotient: Option<Vec<BigUint>>,
    pub random_padding: Option<Vec<BigUint>>,
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
        let secret_hash = FH::hash(
            &params.secret_params,
            &[secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;
        let leaf = FH::hash(&params.leaf_params, &[
            Pubkey::default().to_field_element(),
            F::one(),
            secret_hash,
        ]).map_err(|e| anyhow!("hash error: {}", e))?;

        let friend_nodes_1 = vec![FH::empty_hash(); params.height];
        let mut friend_nodes_2 = vec![FH::empty_hash(); params.height];
        friend_nodes_2[0] = leaf;

        let random_padding = if let Some(param) = &params.rabin_param {
            let mut leaf_len = F::Params::MODULUS_BITS as usize / param.bit_size;
            if F::Params::MODULUS_BITS as usize % param.bit_size != 0 {
                leaf_len += 1;
            }

            Some(vec![BigUint::from(0u64); param.modulus_len - leaf_len - 1])
        } else {
            None
        };

        let origin_inputs = WithdrawOriginInputs {
            mint: Pubkey::default(),
            deposit_amount: 1,
            withdraw_amount: 1,
            leaf_index_1: 0,
            leaf_index_2: 1,
            secret,
            friend_nodes_1,
            friend_nodes_2,
            random_padding,
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

        let secret_hash = FH::hash(
            &params.secret_params,
            &[orig_in.secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;
        let nullifier = FH::hash(
            &params.nullifier_params,
            &[F::from(orig_in.leaf_index_1), orig_in.secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;

        let leaf_1 = FH::hash(
            &params.leaf_params,
            &[orig_in.mint.to_field_element(), F::from(orig_in.deposit_amount), secret_hash],
        ).unwrap();
        let old_root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_1, leaf_1)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();

        let rest_amount = orig_in.deposit_amount - orig_in.withdraw_amount;
        let leaf_2 = FH::hash(
            &params.leaf_params,
            &[orig_in.mint.to_field_element(), F::from(rest_amount), secret_hash],
        ).unwrap();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes_2, leaf_2.clone())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let (random_padding, quotient, cipher) = if let Some(param) = &params.rabin_param {            
            let random_padding = orig_in.random_padding.as_ref().unwrap();
            let preimage = param.gen_preimage_from_leaf(orig_in.leaf_index_1, leaf_1, random_padding);
            let (quotient, cipher) = (&preimage * &preimage).div_rem(&param.modulus);
            let quotient = param.gen_quotient_array(quotient);
            let cipher = param.gen_cipher_array(cipher);

            (Some(random_padding.clone()), Some(quotient), Some(cipher))
        } else {
            (None, None, None)
        };

        let pub_in = WithdrawPublicInputs {
            mint: orig_in.mint,
            withdraw_amount: orig_in.withdraw_amount,
            new_leaf_index: orig_in.leaf_index_2,
            nullifier,
            old_root,
            new_leaf: leaf_2,
            update_nodes,
            cipher,
        };
        let priv_in = WithdrawPrivateInputs {
            deposit_amount: orig_in.deposit_amount,
            secret: orig_in.secret,
            friend_nodes_1,
            friend_nodes_2,
            old_leaf_index: orig_in.leaf_index_1,
            old_leaf: leaf_1,
            quotient,
            random_padding,
        };

        Ok((pub_in, priv_in))
    }
}
