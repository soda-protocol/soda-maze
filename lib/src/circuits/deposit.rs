use ark_std::rc::Rc;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::hasher::FieldHasher;
use super::{FieldHasherGadget, RabinEncryption};
use super::merkle::AddNewLeaf;

pub struct DepositCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    leaf_params: Rc<FH::Parameters>,
    leaf_index: u64,
    deposit_amount: u64,
    leaf: F,
    prev_root: F,
    secret: F,
    proof: AddNewLeaf<F, FH, FHG>,
    encrption: Option<RabinEncryption<F, FH, FHG>>,
}

impl<F, FH, FHG> ConstraintSynthesizer<F> for DepositCircuit<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        // alloc constant
        let leaf_params = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        
        // alloc input
        // withdraw amount bit size of 64 can verify in contract, so no need constrain in circuit
        let leaf_index = FpVar::new_input(cs.clone(), || Ok(F::from(self.leaf_index)))?;
        let deposit_amount = FpVar::new_input(cs.clone(), || Ok(F::from(self.deposit_amount)))?;
        let leaf_input = FpVar::new_input(cs.clone(), || Ok(self.leaf))?;
        let prev_root = FpVar::new_input(cs.clone(), || Ok(self.prev_root))?;

        // alloc witness
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // hash leaf: hash(leaf_index | deposit_amount | secret)
        let leaf = FHG::hash_gadget(
            &leaf_params,
            &[leaf_index.clone(), deposit_amount, secret.clone()],
        )?;
        leaf_input.enforce_equal(&leaf)?;
        // add new leaf proof
        self.proof.synthesize(cs.clone(), leaf_index.clone(), leaf, prev_root)?;

        if let Some(encryption) = self.encrption {
            encryption.synthesize(cs, leaf_index, secret)?;
        }

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
        leaf_params: FH::Parameters,
        inner_params: FH::Parameters,
        leaf_index: u64,
        deposit_amount: u64,
        leaf: F,
        prev_root: F,
        update_nodes: Vec<F>,
        secret: F,
        friend_nodes: Vec<(bool, F)>,
        encrption: Option<RabinEncryption<F, FH, FHG>>,
    ) -> Self {
        Self {
            leaf_params: Rc::new(leaf_params),
            leaf_index,
            deposit_amount,
            leaf,
            prev_root,
            secret,
            proof: AddNewLeaf::new(
                friend_nodes,
                update_nodes,
                inner_params,
            ),
            encrption,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::hasher::poseidon::PoseidonHasherGadget;
    use crate::vanilla::{hasher::{poseidon::PoseidonHasher, FieldHasher}, merkle::gen_merkle_path};
    use super::DepositCircuit;

    const HEIGHT: u8 = 27;

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
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        let inner_params = setup_params_x5_3::<Fr>(Curve::Bn254);
        // deposit data
        let amount = u64::rand(rng);
        let secret = Fr::rand(rng);

        let amount_fp = Fr::from(amount);
        let friend_nodes = get_random_merkle_friends(rng);
        let index_iter = friend_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();
        let leaf = PoseidonHasher::hash(
            &leaf_params,
            &[Fr::from(index), amount_fp, secret],
        ).unwrap();

        let prev_root = gen_merkle_path::<_, PoseidonHasher<Fr>>(
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
            leaf.clone(),
        ).unwrap();

        let deposit = DepositCircuit::<_, _, PoseidonHasherGadget<Fr>>::new(
            leaf_params,
            inner_params,
            index,
            amount,
            leaf,
            prev_root,
            update_nodes,
            secret,
            friend_nodes,
            None,
        );

        let cs = ConstraintSystem::<_>::new_ref();
        deposit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
    }
}