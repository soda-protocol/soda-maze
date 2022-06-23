use ark_std::{cmp::Ordering, rc::Rc};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::hasher::FieldHasher;
use super::FieldHasherGadget;
use super::merkle::{AddNewLeaf, LeafExistance};
use super::uint64::Uint64;

pub struct WithdrawCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    nullifier_params: Rc<FH::Parameters>,
    leaf_params: Rc<FH::Parameters>,
    src_leaf_index: u64,
    dst_leaf_index: u64,
    balance: u64,
    withdraw_amount: u64,
    nullifier: F,
    secret: F,
    prev_root: F,
    dst_leaf: F,
    src_proof: LeafExistance<F, FH, FHG>,
    dst_proof: AddNewLeaf<F, FH, FHG>,
}

impl<F, FH, FHG> ConstraintSynthesizer<F> for WithdrawCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        // alloc constant
        let nullifier_params = FHG::ParametersVar::new_constant(cs.clone(), self.nullifier_params)?;
        let leaf_params = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        
        // alloc input
        // withdraw amount bit size of 64 can verify in contract, so no need constrain in circuit
        let withdraw_amount = FpVar::new_input(cs.clone(), || Ok(F::from(self.withdraw_amount)))?;
        let nullifier_input = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        let dst_leaf_index = FpVar::new_input(cs.clone(), || Ok(F::from(self.dst_leaf_index)))?;
        let dst_leaf_input = FpVar::new_input(cs.clone(), || Ok(self.dst_leaf))?;
        let prev_root = FpVar::new_input(cs.clone(), || Ok(self.prev_root))?;

        // alloc witness
        let src_leaf_index = FpVar::new_witness(cs.clone(), || Ok(F::from(self.src_leaf_index)))?;
        let balance = Uint64::new_witness(cs.clone(), || Ok(self.balance))?;
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // restrain withdraw amount is less and equal than balance
        let balance = balance.fp_var().clone();
        balance.enforce_cmp_unchecked(
            &withdraw_amount,
            Ordering::Greater,
            true,
        )?;
        let rest_amount = &balance - withdraw_amount;

        // hash nullifier: hash(leaf_index | secret)
        let nullifier = FHG::hash_gadget(
            &nullifier_params,
            &[src_leaf_index.clone(), secret.clone()],
        )?;
        nullifier.enforce_equal(&nullifier_input)?;

        // hash leaf: hash(leaf_index | balance | secret)
        let src_leaf = FHG::hash_gadget(
            &leaf_params,
            &[src_leaf_index.clone(), balance, secret.clone()],
        )?;
        // gen existance proof
        self.src_proof.synthesize(
            cs.clone(),
            src_leaf_index,
            src_leaf,
            prev_root.clone(),
        )?;

        // hash new back deposit data leaf: hash(leaf_index | rest_amount | secret)
        let dst_leaf = FHG::hash_gadget(
            &leaf_params,
            &[dst_leaf_index.clone(), rest_amount, secret],
        )?;
        dst_leaf_input.enforce_equal(&dst_leaf)?;
        // gen add new leaf proof
        self.dst_proof.synthesize(cs.clone(), dst_leaf_index, dst_leaf, prev_root)
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
        nullifier_params: FH::Parameters,
        leaf_params: FH::Parameters,
        inner_params: FH::Parameters,
        src_leaf_index: u64,
        dst_leaf_index: u64,
        balance: u64,
        withdraw_amount: u64,
        nullifier: F,
        secret: F,
        prev_root: F,
        dst_leaf: F,
        update_nodes: Vec<F>,
        src_neighbor_nodes: Vec<(bool, F)>,
        dst_neighbor_nodes: Vec<(bool, F)>,
    ) -> Self {
        Self {
            nullifier_params: Rc::new(nullifier_params),
            leaf_params: Rc::new(leaf_params),
            src_leaf_index,
            dst_leaf_index,
            balance,
            withdraw_amount,
            nullifier,
            secret,
            prev_root,
            dst_leaf,
            src_proof: LeafExistance::new(
                src_neighbor_nodes,
                inner_params.clone(),
            ),
            dst_proof: AddNewLeaf::new(
                dst_neighbor_nodes,
                update_nodes,
                inner_params,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::rand::Rng;
    use ark_std::{test_rng, UniformRand};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::poseidon::PoseidonHasherGadget;
    use crate::vanilla::merkle::gen_merkle_path;
    use crate::vanilla::hasher::{poseidon::PoseidonHasher, FieldHasher};
    use super::WithdrawCircuit;

    const HEIGHT: u8 = 24;

    fn get_random_merkle_neighbors<R: Rng + ?Sized>(rng: &mut R) -> Vec<(bool, Fr)> {
        let mut neighbor_nodes = vec![(bool::rand(rng), Fr::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            neighbor_nodes.push((bool::rand(rng), Fr::rand(rng)));
        }

        neighbor_nodes
    }

    fn test_withdraw_inner<R: Rng + ?Sized>(rng: &mut R, deposit_amount: u64, withdraw_amount: u64) -> ConstraintSystemRef<Fr> {
        let nullifier_params = setup_params_x5_3(Curve::Bn254);
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        let inner_params = setup_params_x5_3(Curve::Bn254);
        // deposit data
        let secret = Fr::rand(rng);
        let rest_amount = deposit_amount.saturating_sub(withdraw_amount);

        let mut src_neighbor_nodes = get_random_merkle_neighbors(rng);
        src_neighbor_nodes[0] = (false, PoseidonHasher::empty_hash());
        let index_iter = src_neighbor_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let src_index = BitVec::<u8>::from_iter(index_iter).load_le::<u64>();
        let src_leaf = PoseidonHasher::hash(
            &leaf_params,
            &[Fr::from(src_index), Fr::from(deposit_amount), secret],
        ).unwrap();

        let mut dst_neighbor_nodes = src_neighbor_nodes.clone();
        dst_neighbor_nodes[0] = (true, src_leaf);
        let dst_index = src_index + 1;
        let dst_leaf = PoseidonHasher::hash(
            &leaf_params,
            &[Fr::from(dst_index), Fr::from(rest_amount), secret],
        ).unwrap();

        let nullifier = PoseidonHasher::hash(
            &nullifier_params,
            &[Fr::from(src_index), secret],
        ).unwrap();

        let prev_root = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &src_neighbor_nodes,
            src_leaf,
        )
        .unwrap()
        .last()
        .unwrap()
        .clone();

        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &dst_neighbor_nodes,
            dst_leaf,
        ).unwrap();

        let withdrawal = WithdrawCircuit::<_, _, PoseidonHasherGadget<_>>::new(
            nullifier_params,
            leaf_params,
            inner_params,
            src_index,
            dst_index,
            deposit_amount,
            withdraw_amount,
            nullifier,
            secret,
            prev_root,
            dst_leaf,
            update_nodes,
            src_neighbor_nodes,
            dst_neighbor_nodes,
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
