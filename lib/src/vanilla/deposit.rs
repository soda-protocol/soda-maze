use anyhow::{anyhow, Result};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;

use super::{hasher::FieldHasher, VanillaProof, merkle::gen_merkle_path};
use super::encryption;
use super::encryption::{EncryptionConstParams, EncryptionOriginInputs};
use super::encryption::{EncryptionPublicInputs, EncryptionPrivateInputs};

#[derive(Default)]
pub struct DepositVanillaProof<F: PrimeField, FH: FieldHasher<F>> {
    _f: PhantomData<F>,
    _fh: PhantomData<FH>,
}

pub struct DepositConstParams<F: PrimeField, FH: FieldHasher<F>> {
    pub leaf_params: FH::Parameters,
    pub inner_params: FH::Parameters,
    pub height: usize,
    pub encryption: Option<EncryptionConstParams<F, FH>>,
}

#[derive(Clone)]
pub struct DepositOriginInputs<F: PrimeField> {
    pub leaf_index: u64,
    pub deposit_amount: u64,
    pub secret: F,
    pub friend_nodes: Vec<F>,
    pub encryption: Option<EncryptionOriginInputs>,
}

#[derive(Clone)]
pub struct DepositPublicInputs<F: PrimeField> {
    pub leaf_index: u64,
    pub deposit_amount: u64,
    pub leaf: F,
    pub prev_root: F,
    pub update_nodes: Vec<F>,
    pub encryption: Option<EncryptionPublicInputs<F>>,
}

#[derive(Clone)]
pub struct DepositPrivateInputs<F: PrimeField> {
    pub secret: F,
    pub friend_nodes: Vec<(bool, F)>,
    pub encryption: Option<EncryptionPrivateInputs>,
}

impl<F, FH> VanillaProof<F> for DepositVanillaProof<F, FH>
where
    F: PrimeField,
    FH: FieldHasher<F>,
{
    type ConstParams = DepositConstParams<F, FH>;
    type OriginInputs = DepositOriginInputs<F>;
    type PublicInputs = DepositPublicInputs<F>;
    type PrivateInputs = DepositPrivateInputs<F>;

    fn blank_proof(params: &Self::ConstParams) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        let enc_orig_in = params.encryption
            .as_ref()
            .map(|params| encryption::gen_origin_inputs(params));

        let origin_inputs = DepositOriginInputs {
            leaf_index: 0,
            deposit_amount: 1,
            secret: F::zero(),
            friend_nodes: vec![FH::empty_hash(); params.height],
            encryption: enc_orig_in,
        };

        Self::generate_vanilla_proof(params, &origin_inputs)
    }

    fn generate_vanilla_proof(
        params: &DepositConstParams<F, FH>,
        orig_in: &DepositOriginInputs<F>,
    ) -> Result<(Self::PublicInputs, Self::PrivateInputs)> {
        assert_eq!(orig_in.friend_nodes.len(), params.height);
        assert!(orig_in.leaf_index < (1 << params.height));
        assert!(orig_in.deposit_amount > 0, "deposit amount must be greater than 0");

        let friend_nodes = orig_in.friend_nodes
            .iter()
            .enumerate()
            .map(|(layer, node)| {
                let is_left = ((orig_in.leaf_index >> layer) & 1) == 1;
                Ok((is_left, node.clone()))
            })
            .collect::<Result<Vec<_>>>()?;

        let leaf = FH::hash(&params.leaf_params,
            &[F::from(orig_in.leaf_index), F::from(orig_in.deposit_amount), orig_in.secret],
        ).map_err(|e| anyhow!("hash error: {}", e))?;

        let prev_root = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes, FH::empty_hash())
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?
            .last()
            .unwrap()
            .clone();
        let update_nodes = gen_merkle_path::<_, FH>(&params.inner_params, &friend_nodes, leaf)
            .map_err(|e| anyhow!("gen merkle path error: {:?}", e))?;

        let encryption = params.encryption
            .as_ref()
            .zip(orig_in.encryption.as_ref())
            .map(|(enc_params, enc_orig_in)| {
                encryption::generate_vanilla_proof(enc_params, enc_orig_in, orig_in.leaf_index, orig_in.secret)
            })
            .transpose()?;
        let (enc_pub_in, enc_priv_in) = if let Some((pub_in, priv_in)) = encryption {
            (Some(pub_in), Some(priv_in))
        } else {
            (None, None)
        };

        let pub_in = DepositPublicInputs {
            leaf_index: orig_in.leaf_index,
            deposit_amount: orig_in.deposit_amount,
            leaf,
            prev_root,
            update_nodes,
            encryption: enc_pub_in,
        };
        let priv_in = DepositPrivateInputs {
            secret: orig_in.secret,
            friend_nodes,
            encryption: enc_priv_in,
        };

        Ok((pub_in, priv_in))
    }
}
