use std::marker::PhantomData;

use ark_std::rc::Rc;
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, boolean::Boolean, alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};

use crate::{circuits::hasher::FieldHasherGadget, primitives::hasher::FieldHasher};

use super::gen_merkle_path_gadget;

pub struct AddNewLeaf<F, FH, FHG, const HEIGHT: u8>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    old_root: F,
    new_leaf: F,
    leaf_index: u64,
    friend_nodes: Vec<(bool, F)>,
    update_nodes: Vec<F>,
	inner_params: Rc<FH::Parameters>,
    _h: PhantomData<FHG>,
}

impl<F, FH, FHG, const HEIGHT: u8> AddNewLeaf<F, FH, FHG, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>, 
{
    pub fn new(
        old_root: F,
        new_leaf: F,
        leaf_index: u64,
        friend_nodes: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        inner_params: FH::Parameters,
    ) -> Self {
        assert_eq!(friend_nodes.len(), HEIGHT as usize, "invalid friend nodes length");
        assert_eq!(update_nodes.len(),HEIGHT as usize, "invalid update nodes length");

        Self {
            old_root,
            new_leaf,
            leaf_index,
            friend_nodes,
            update_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }
    
    pub fn generate_constraints(self, cs: ConstraintSystemRef<F>, leaf_var: FpVar<F>) -> Result<(), SynthesisError> {
        let cs = &cs;
        // alloc constants
        let empty_leaf_var = FHG::empty_hash_var();
        let inner_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc public inputs
        let leaf_index_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.leaf_index)))?;
        let new_leaf_var = FpVar::new_input(cs.clone(), || Ok(self.new_leaf))?;
        let old_root_var = FpVar::new_input(cs.clone(), || Ok(self.old_root))?;
        let new_nodes_vars = self.update_nodes
            .into_iter()
            .map(|node| FpVar::new_input(cs.clone(), || Ok(node)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // alloc friends var
        let friends_var = self.friend_nodes
            .into_iter()
            .map(|(is_left, node)| {
                let is_left = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                // friend node can be alloc as public, but no need to do it here
                let node = FpVar::new_witness(cs.clone(), || Ok(node))?;

                Ok((is_left, node))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // leaf index constrain
        let position = friends_var
            .iter()
            .map(|(is_left, _)| is_left.clone())
            .collect::<Vec<_>>();
        let position_var = Boolean::le_bits_to_fp_var(&position)?;
        leaf_index_var.enforce_equal(&position_var)?;
        
        // old root constrain
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG, HEIGHT>(&inner_params_var, &friends_var, empty_leaf_var)?;
        merkle_paths.last().unwrap().enforce_equal(&old_root_var)?;

        // leaf change
        new_leaf_var.enforce_equal(&leaf_var)?;
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG, HEIGHT>(&inner_params_var, &friends_var, leaf_var)?;
        // new paths should restrain to input
        merkle_paths
            .into_iter()
            .zip(new_nodes_vars)
            .try_for_each(|(node, input_node)| node.enforce_equal(&input_node))?;

        Ok(())
    }
}

pub struct LeafExistance<F, FH, FHG, const HEIGHT: u8>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    root: F,
    friend_nodes: Vec<(bool, F)>,
	inner_params: Rc<FH::Parameters>,
    _h: PhantomData<FHG>,
}

impl<F, FH, FHG, const HEIGHT: u8> LeafExistance<F, FH, FHG, HEIGHT>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    pub fn new(
        root: F,
        friend_nodes: Vec<(bool, F)>,
        inner_params: FH::Parameters,
    ) -> Self {
        assert_eq!(friend_nodes.len(), HEIGHT as usize, "invalid friend nodes length");

        Self {
            root,
            friend_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }

    pub fn generate_constraints(self, cs: ConstraintSystemRef<F>, leaf_var: FpVar<F>) -> Result<(), SynthesisError> {
        let cs = &cs;
        // alloc constants
        let inner_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc public inputs
        let root_var = FpVar::new_input(cs.clone(), || Ok(self.root))?;

        // alloc friends var
        let friends_var = self.friend_nodes
            .into_iter()
            .map(|(is_left, node)| {
                let is_left = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                let node = FpVar::new_witness(cs.clone(), || Ok(node))?;

                Ok((is_left, node))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG, HEIGHT>(&inner_params_var, &friends_var, leaf_var)?;
        // old root should restrain to input
        merkle_paths.last().unwrap().enforce_equal(&root_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fq;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};
    use bitvec::field::BitField;
    use bitvec::prelude::BitVec;

    use crate::{circuits::poseidon::PoseidonHasherGadget, primitives::hasher::FieldHasher};
    use crate::primitives::poseidon::PoseidonHasher;
    use crate::primitives::merkle::gen_merkle_path;
    use super::{LeafExistance, AddNewLeaf};

    const HEIGHT: u8 = 20;

    fn get_random_merkle_friends(rng: &mut StdRng) -> Vec<(bool, Fq)> {
        let mut friend_nodes = vec![(bool::rand(rng), Fq::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            friend_nodes.push((bool::rand(rng), Fq::rand(rng)));
        }

        friend_nodes
    }

    #[test]
    fn test_leaf_existance() {
        let rng = &mut test_rng();
        let params = setup_params_x5_3::<Fq>(Curve::Bn254);
        let leaf = Fq::rand(rng);
        let friend_nodes = get_random_merkle_friends(rng);
        let merkle_path = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &params,
            &friend_nodes,
            leaf.clone(),
        ).unwrap();
        let root = merkle_path.last().unwrap().clone();
        let existance = LeafExistance::<_, _, PoseidonHasherGadget<Fq>, HEIGHT>::new(
            root,
            friend_nodes,
            params,
        );

        let cs = ConstraintSystem::<Fq>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        existance.generate_constraints(cs.clone(), leaf_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
        println!("instance: {}", cs.num_instance_variables());
        println!("witness: {}", cs.num_witness_variables());
    }

    #[test]
    fn test_add_new_leaf() {
        let rng = &mut test_rng();
        let params = setup_params_x5_3(Curve::Bn254);
        let friend_nodes = get_random_merkle_friends(rng);
        let index_iter = friend_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &params,
            &friend_nodes,
            PoseidonHasher::empty_hash(),
        ).unwrap();
        let old_root = update_nodes.last().unwrap().clone();
        let new_leaf = Fq::rand(rng);
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fq>, HEIGHT>(
            &params,
            &friend_nodes,
            new_leaf.clone(),
        ).unwrap();
        let add_new_leaf = AddNewLeaf::<_, _, PoseidonHasherGadget<Fq>, HEIGHT>::new(
            old_root,
            new_leaf.clone(),
            index,
            friend_nodes,
            update_nodes,
            params,
        );

        let cs = ConstraintSystem::<Fq>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(new_leaf)).unwrap();
        add_new_leaf.generate_constraints(cs.clone(), leaf_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
        println!("instance: {}", cs.num_instance_variables());
        println!("witness: {}", cs.num_witness_variables());
    }
}