use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_std::rc::Rc;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::{array::Pubkey, hasher::FieldHasher};
use super::FieldHasherGadget;
use super::merkle::{AddNewLeaf, LeafExistance};
use super::uint64::Uint64;

pub struct DepositCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    mint: Pubkey,
    amount: u64,
    secret: F,
    leaf_params: Rc<FH::Parameters>,
    merkle_proof: AddNewLeaf<F, FH, FHG>,
}

impl<F, FH, FHG> ConstraintSynthesizer<F> for DepositCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
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
        self.merkle_proof.synthesize(cs.clone(), leaf_var)?;

        Ok(())
    }
}

impl<F, FH, FHG> DepositCircuit<F, FH, FHG>
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
}

pub struct WithdrawCircuit<F, FH, FHG>
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
    nullifier_params: Rc<FH::Parameters>,
    leaf_params: Rc<FH::Parameters>,
    merkle_proof: LeafExistance<F, FH, FHG>,
}

impl<F, FH, FHG> ConstraintSynthesizer<F> for WithdrawCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        // alloc constant
        let leaf_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        let nullifier_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.nullifier_params)?;
        // alloc input
        let mint_var = FpVar::new_input(cs.clone(), || Ok(self.mint.to_field_element::<F>()))?;
        let withdraw_amount_var = Uint64::new_input(cs.clone(), || Ok(self.withdraw_amount))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        // alloc witness
        let deposit_amount_var = Uint64::new_witness(cs.clone(), || Ok(self.deposit_amount))?;
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // hash for leaf
        let secret_hash_var = FHG::hash_gadget(&nullifier_params_var, &[secret_var.clone()])?;
        secret_hash_var.enforce_equal(&nullifier_var)?;

        // restrain withdraw amount is less and equal than deposit amount
        withdraw_amount_var.is_less_and_equal_than(&deposit_amount_var)?;

        let preimage = vec![mint_var, deposit_amount_var.fp_var().clone(), secret_var];
        // withdrawal proof
        let leaf_var = FHG::hash_gadget(&leaf_params_var, &preimage)?;
        self.merkle_proof.synthesize(cs.clone(), leaf_var)?;

        Ok(())
    }
}

impl<F, FH, FHG> WithdrawCircuit<F, FH, FHG>
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
        nullifier_params: FH::Parameters,
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
            nullifier_params: Rc::new(nullifier_params),
            leaf_params: Rc::new(leaf_params),
            merkle_proof: LeafExistance::new(
                root,
                friend_nodes,
                inner_params,
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_2, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::poseidon::PoseidonHasherGadget;
    use crate::vanilla::{array::Pubkey, hasher::{poseidon::PoseidonHasher, FieldHasher}, merkle::gen_merkle_path};
    use super::{DepositCircuit, WithdrawCircuit};

    const HEIGHT: u8 = 24;

    fn get_random_merkle_friends(rng: &mut StdRng) -> Vec<(bool, Fr)> {
        let mut friend_nodes = vec![(bool::rand(rng), Fr::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            friend_nodes.push((bool::rand(rng), Fr::rand(rng)));
        }

        friend_nodes
    }

    #[test]
    fn test_deposit() {
        let rng = &mut test_rng();
        let inner_params = setup_params_x5_3::<Fr>(Curve::Bn254);
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        // deposit data
        let mint = Pubkey::new(<[u8; 32]>::rand(rng));
        let amount = u64::rand(rng);
        let secret = Fr::rand(rng);

        let mint_fp = mint.to_field_element::<Fr>();
        let amount_fp = Fr::from(amount);
        let preimage = vec![mint_fp, amount_fp, secret];
        let new_leaf = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();
        let friend_nodes = get_random_merkle_friends(rng);
        let index_iter = friend_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();

        let old_root = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes,
            PoseidonHasher::empty_hash(),
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();
        
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes,
            new_leaf.clone(),
        ).unwrap();

        let deposit = DepositCircuit::<_, _, PoseidonHasherGadget<Fr>>::new(
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

    fn test_withdraw_inner(rng: &mut StdRng, deposit_amount: u64, withdraw_amount: u64) -> ConstraintSystemRef<Fr> {
        let nullifier_params = setup_params_x5_2(Curve::Bn254);
        let inner_params = setup_params_x5_3::<Fr>(Curve::Bn254);
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        // deposit data
        let mint = Pubkey::new(<[u8; 32]>::rand(rng));
        let secret = Fr::rand(rng);

        let mint_fp = mint.to_field_element::<Fr>();
        let deposit_amount_fp = Fr::from(deposit_amount);
        let preimage = vec![mint_fp, deposit_amount_fp, secret];
        let leaf = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();
        let nullifier = PoseidonHasher::hash(&nullifier_params, &[secret]).unwrap();
        let friend_nodes = get_random_merkle_friends(rng);

        let root = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes,
            leaf.clone(),
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();

        let withdrawal = WithdrawCircuit::<_, _, PoseidonHasherGadget<Fr>>::new(
            mint,
            withdraw_amount,
            deposit_amount,
            secret,
            nullifier,
            nullifier_params,
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
