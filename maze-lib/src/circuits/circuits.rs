use ark_std::{cmp::Ordering, rc::Rc};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::{array::Pubkey, hasher::FieldHasher};
use super::{FieldHasherGadget, RabinEncryption};
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
    proof: AddNewLeaf<F, FH, FHG>,
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
        self.proof.synthesize(cs.clone(), leaf_var, None)?;

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
            proof: AddNewLeaf::new(
                Some(old_root),
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
    nullifier: F,
    old_secret: F,
    new_secret: F,
    leaf_params: Rc<FH::Parameters>,
    nullifier_params: Rc<FH::Parameters>,
    proof_1: LeafExistance<F, FH, FHG>,
    proof_2: AddNewLeaf<F, FH, FHG>,
    rabin_encrytion: Option<RabinEncryption<F>>,
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
        // withdraw amount bit size of 64 can verify in contract, so no need constrain in circuit
        let withdraw_amount_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.withdraw_amount)))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        // alloc witness
        let deposit_amount_var = Uint64::new_witness(cs.clone(), || Ok(self.deposit_amount))?;
        let old_secret_var = FpVar::new_witness(cs.clone(), || Ok(self.old_secret))?;
        let new_secret_var = FpVar::new_witness(cs.clone(), || Ok(self.new_secret))?;

        // restrain withdraw amount is less and equal than deposit amount
        let deposit_amount_var = deposit_amount_var.fp_var().clone();
        deposit_amount_var.enforce_cmp_unchecked(
            &withdraw_amount_var,
            Ordering::Greater,
            true,
        )?;
        let rest_amount_var = &deposit_amount_var - withdraw_amount_var;

        // hash secret
        let secret_hash_var = FHG::hash_gadget(&nullifier_params_var, &[old_secret_var.clone()])?;
        secret_hash_var.enforce_equal(&nullifier_var)?;

        // hash origin data to leaf
        let preimage = vec![mint_var.clone(), deposit_amount_var, old_secret_var];
        // existance proof
        let leaf_var = FHG::hash_gadget(&leaf_params_var, &preimage)?;
        // if need rabin encrytion for leaf
        if let Some(rabin_encrytion) = self.rabin_encrytion {
            rabin_encrytion.synthesize(cs.clone(), leaf_var.clone())?;
        }
        let root_var = self.proof_1.synthesize(cs.clone(), leaf_var)?;

        // hash new back deposit data leaf
        let preimage = vec![mint_var, rest_amount_var, new_secret_var];
        // add new leaf proof
        let leaf_var = FHG::hash_gadget(&leaf_params_var, &preimage)?;
        self.proof_2.synthesize(cs.clone(), leaf_var, Some(root_var))?;

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
        nullifier: F,
        old_secret: F,
        new_secret: F,
        leaf_index_2: u64,
        leaf_2: F,
        old_root: F,
        friend_nodes_1: Vec<(bool, F)>,
        friend_nodes_2: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        nullifier_params: FH::Parameters,
        leaf_params: FH::Parameters,
        inner_params: FH::Parameters,
        rabin_encrytion: Option<RabinEncryption<F>>,
    ) -> Self {
        Self {
            mint,
            withdraw_amount,
            deposit_amount,
            nullifier,
            old_secret,
            new_secret,
            nullifier_params: Rc::new(nullifier_params),
            leaf_params: Rc::new(leaf_params),
            proof_1: LeafExistance::new(
                old_root,
                friend_nodes_1,
                inner_params.clone(),
            ),
            proof_2: AddNewLeaf::new(
                None,
                leaf_2,
                leaf_index_2,
                friend_nodes_2,
                update_nodes,
                inner_params,
            ),
            rabin_encrytion,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4, setup_params_x5_2};
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
        let old_secret = Fr::rand(rng);
        let new_secret = Fr::rand(rng);
        let nullifier = PoseidonHasher::hash(&nullifier_params, &[old_secret]).unwrap();
        let rest_amount = deposit_amount.saturating_sub(withdraw_amount);

        let mint_fp = mint.to_field_element::<Fr>();
        let preimage = vec![mint_fp, Fr::from(deposit_amount), old_secret];
        let leaf_1 = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();
        let preimage = vec![mint_fp, Fr::from(rest_amount), new_secret];
        let leaf_2 = PoseidonHasher::hash(&leaf_params, &preimage[..]).unwrap();

        let mut friend_nodes_1 = get_random_merkle_friends(rng);
        friend_nodes_1[0] = (false, PoseidonHasher::empty_hash());
        let mut friend_nodes_2 = friend_nodes_1.clone();
        friend_nodes_2[0] = (true, leaf_1);
        let index_iter = friend_nodes_1.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index_2 = BitVec::<u8>::from_iter(index_iter).load_le::<u64>() + 1;

        let old_root = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes_1,
            leaf_1,
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();

        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes_2,
            leaf_2.clone(),
        ).unwrap();

        let withdrawal = WithdrawCircuit::<_, _, PoseidonHasherGadget<Fr>>::new(
            mint,
            withdraw_amount,
            deposit_amount,
            nullifier,
            old_secret,
            new_secret,
            index_2,
            leaf_2,
            old_root,
            friend_nodes_1,
            friend_nodes_2,
            update_nodes,
            nullifier_params,
            leaf_params,
            inner_params,
            None,
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
        println!("constraints: {}", cs.num_constraints());

        let withdraw_amount = deposit_amount - deposit_amount / 2;
        let cs = test_withdraw_inner(rng, deposit_amount, withdraw_amount);
        assert!(cs.is_satisfied().unwrap());

        let withdraw_amount = deposit_amount + 1;
        let cs = test_withdraw_inner(rng, deposit_amount, withdraw_amount);
        assert!(!cs.is_satisfied().unwrap());
    }
}
