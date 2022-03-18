mod uint64;
mod merkle;

pub mod hasher;
pub mod poseidon;

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_std::rc::Rc;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};

use crate::primitives::{array::Pubkey, hasher::FieldHasher};

use hasher::FieldHasherGadget;
use merkle::{AddNewLeaf, LeafExistance};
use uint64::Uint64;

pub struct Deposit<F, FH, FHG, const HEIGHT: u8>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    mint: Pubkey,
    amount: u64,
    secret: F,
    leaf_params: Rc<FH::Parameters>,
    merkle_proof: AddNewLeaf<F, FH, FHG, HEIGHT>,
}

impl<F, FH, FHG, const HEIGHT: u8> Deposit<F, FH, FHG, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mint: Pubkey,
        amount: u64,
        secret: F,
        leaf_params: FH::Parameters,
        leaf_index: u64,
        old_root: F,
        new_leaf: F,
        friend_nodes: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        inner_params: FH::Parameters,
    ) -> Self {
        Self {
            mint,
            amount,
            secret,
            leaf_params: Rc::new(leaf_params),
            merkle_proof: AddNewLeaf::new(
                old_root,
                new_leaf,
                leaf_index,
                friend_nodes,
                update_nodes,
                inner_params,
            ),
        }
    }

    pub fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // alloc const
        let leaf_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        // alloc input
        let mint_var = FpVar::new_input(cs.clone(), || Ok(self.mint.to_field_element::<F>()))?;
        let amount_var = Uint64::new_input(cs.clone(), || Ok(self.amount))?;
        // alloc witness
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // hash for leaf
        let preimage = vec![mint_var, amount_var.fp_var().clone(), secret_var];
        let leaf_var = FHG::hash_gadget(&leaf_params_var, &preimage)?;

        // deposit proof
        self.merkle_proof.generate_constraints(cs.clone(), leaf_var)?;

        Ok(())
    }
}

pub struct Withdrawal<F, FH, FHG, const HEIGHT: u8>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    mint: Pubkey,
    withdraw_amount: u64,
    deposit_amount: u64,
    secret: F,
    nullifier: F,
    leaf_params: Rc<FH::Parameters>,
    merkle_proof: LeafExistance<F, FH, FHG, HEIGHT>,
}

impl<F, FH, FHG, const HEIGHT: u8> Withdrawal<F, FH, FHG, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mint: Pubkey,
        withdraw_amount: u64,
        deposit_amount: u64,
        secret: F,
        nullifier: F,
        leaf_params: FH::Parameters,
        root: F,
        friend_nodes: Vec<(bool, F)>,
        inner_params: FH::Parameters,
    ) -> Self {
        Self {
            mint,
            withdraw_amount,
            deposit_amount,
            secret,
            nullifier,
            leaf_params: Rc::new(leaf_params),
            merkle_proof: LeafExistance::new(
                root,
                friend_nodes,
                inner_params,
            ),
        }
    }

    pub fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // alloc constant
        let leaf_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        // alloc input
        let mint_var = FpVar::new_input(cs.clone(), || Ok(self.mint.to_field_element::<F>()))?;
        let withdraw_amount_var = Uint64::new_input(cs.clone(), || Ok(self.withdraw_amount))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        // alloc witness
        let deposit_amount_var = Uint64::new_witness(cs.clone(), || Ok(self.deposit_amount))?;
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // hash for leaf
        let secret_hash_var = FHG::hash_gadget(&leaf_params_var, &[secret_var.clone()])?;
        secret_hash_var.enforce_equal(&nullifier_var)?;

        // restrain withdraw amount is less and equal than deposit amount
        withdraw_amount_var.is_less_and_equal_than(&deposit_amount_var)?;

        let preimage = vec![mint_var, deposit_amount_var.fp_var().clone(), secret_var];
        // withdrawal proof
        let leaf_var = FHG::hash_gadget(&leaf_params_var, &preimage)?;
        self.merkle_proof.generate_constraints(cs.clone(), leaf_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fq;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve, setup_params_x5_5};
use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::poseidon::PoseidonHasherGadget;
    use crate::primitives::array::Pubkey;
    use crate::primitives::hasher::FieldHasher;
    use crate::primitives::merkle::gen_merkle_path;
    use crate::primitives::poseidon::PoseidonHasher;

    use super::{Deposit, Withdrawal};

    const HEIGHT: u8 = 20;

    fn get_random_merkle_friends(rng: &mut StdRng) -> Vec<(bool, Fq)> {
        let mut friend_nodes = vec![(bool::rand(rng), Fq::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            friend_nodes.push((bool::rand(rng), Fq::rand(rng)));
        }

        friend_nodes
    }

    #[test]
    fn test_deposit() {
        let rng = &mut test_rng();
        let inner_params = setup_params_x5_3::<Fq>(Curve::Bn254);
        let leaf_params = setup_params_x5_5::<Fq>(Curve::Bn254);
        // deposit data
        let mint = Pubkey::new(<[u8; 32]>::rand(rng));
        let amount = u64::rand(rng);
        let secret = Fq::rand(rng);

        let mint_fp = mint.to_field_element::<Fq>();
        let amount_fp = Fq::from(amount);
        let preimage = vec![mint_fp, amount_fp, secret];
        let new_leaf = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();
        let friend_nodes = get_random_merkle_friends(rng);
        let index_iter = friend_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();

        let old_root = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &inner_params,
            &friend_nodes,
            PoseidonHasher::empty_hash(),
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();
        
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &inner_params,
            &friend_nodes,
            new_leaf.clone(),
        ).unwrap();

        let deposit = Deposit::<_, _, PoseidonHasherGadget<Fq>, HEIGHT>::new(
            mint,
            amount,
            secret,
            leaf_params,
            index,
            old_root.clone(),
            new_leaf.clone(),
            friend_nodes,
            update_nodes,
            inner_params,
        );

        let cs = ConstraintSystem::<_>::new_ref();
        deposit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
        println!("instance: {}", cs.num_instance_variables());
        println!("witness: {}", cs.num_witness_variables());
    }

    fn test_withdraw_inner(rng: &mut StdRng, deposit_amount: u64, withdraw_amount: u64) -> ConstraintSystemRef<Fq> {
        let inner_params = setup_params_x5_3::<Fq>(Curve::Bn254);
        let leaf_params = setup_params_x5_5::<Fq>(Curve::Bn254);
        // deposit data
        let mint = Pubkey::new(<[u8; 32]>::rand(rng));
        let secret = Fq::rand(rng);

        let mint_fp = mint.to_field_element::<Fq>();
        let deposit_amount_fp = Fq::from(deposit_amount);
        let preimage = vec![mint_fp, deposit_amount_fp, secret];
        let leaf = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();
        let nullifier = PoseidonHasher::hash(&leaf_params, &[secret]).unwrap();
        let friend_nodes = get_random_merkle_friends(rng);

        let root = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &inner_params,
            &friend_nodes,
            leaf.clone(),
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();

        let withdrawal = Withdrawal::<_, _, PoseidonHasherGadget<Fq>, HEIGHT>::new(
            mint,
            withdraw_amount,
            deposit_amount,
            secret,
            nullifier,
            leaf_params,
            root,
            friend_nodes,
            inner_params,
        );

        let cs = ConstraintSystem::<_>::new_ref();
        withdrawal.generate_constraints(cs.clone()).unwrap();

        cs
    }

    #[test]
    fn test_withdraw() {
        let rng = &mut test_rng();
        let deposit_amount = u64::rand(rng);

        let withdraw_amount = deposit_amount;
        let cs = test_withdraw_inner(rng, deposit_amount, withdraw_amount);
        assert!(cs.is_satisfied().unwrap());

        let withdraw_amount = deposit_amount - deposit_amount / 2;
        let cs = test_withdraw_inner(rng, deposit_amount, withdraw_amount);
        assert!(cs.is_satisfied().unwrap());

        let withdraw_amount = deposit_amount + 1;
        let cs = test_withdraw_inner(rng, deposit_amount, withdraw_amount);
        assert!(!cs.is_satisfied().unwrap());
    }
}
