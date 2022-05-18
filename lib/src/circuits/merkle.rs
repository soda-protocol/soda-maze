use ark_std::{rc::Rc, marker::PhantomData};
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, boolean::Boolean, alloc::AllocVar, select::CondSelectGadget, fields::fp::FpVar};
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef};

use crate::vanilla::hasher::FieldHasher;
use super::FieldHasherGadget;

fn gen_merkle_path_gadget<F, FH, FHG>(
    inner_params: &FHG::ParametersVar,
    friends: &[(Boolean<F>, FpVar<F>)],
    leaf_hash: FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    // Check levels between leaf level and root.
    let mut previous_hash = leaf_hash;
    friends
        .iter()
        .map(|(is_left, friend_hash)| {
            let left_hash = FpVar::conditionally_select(
                is_left,
                friend_hash,
                &previous_hash,
            )?;
            let right_hash = FpVar::conditionally_select(
                is_left,
                &previous_hash,
                friend_hash,
            )?;

            previous_hash = FHG::hash_two_gadget(inner_params, left_hash, right_hash)?;

            Ok(previous_hash.clone())
        })
        .collect()
}

pub struct AddNewLeaf<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    new_leaf: F,
    leaf_index: u64,
    friend_nodes: Vec<(bool, F)>,
    update_nodes: Vec<F>,
	inner_params: Rc<FH::Parameters>,
    _h: PhantomData<FHG>,
}

impl<F, FH, FHG> AddNewLeaf<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>, 
{
    pub fn new(
        new_leaf: F,
        leaf_index: u64,
        friend_nodes: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        inner_params: FH::Parameters,
    ) -> Self {
        assert_eq!(friend_nodes.len(), update_nodes.len(), "friend nodes length should equals to update nodes length");

        Self {
            new_leaf,
            leaf_index,
            friend_nodes,
            update_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }
    
    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<F>,
        leaf_var: FpVar<F>,
        old_root_var: FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let cs = &cs;
        // alloc constants
        let inner_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc public var
        let new_leaf_index_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.leaf_index)))?;
        let new_leaf_var = FpVar::new_input(cs.clone(), || Ok(self.new_leaf))?;
        let new_nodes_vars = self.update_nodes
            .into_iter()
            .map(|node| FpVar::new_input(cs.clone(), || Ok(node)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        // alloc witness var
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
        new_leaf_index_var.enforce_equal(&position_var)?;
        
        // old root constrain
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params_var,
            &friends_var,
            FHG::empty_hash_var(),
        )?;
        merkle_paths.last().unwrap().enforce_equal(&old_root_var)?;

        // leaf change
        new_leaf_var.enforce_equal(&leaf_var)?;
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params_var,
            &friends_var,
            leaf_var,
        )?;
        // new paths should restrain to input
        new_nodes_vars
            .iter()
            .zip(merkle_paths)
            .try_for_each(|(input_node, node)| input_node.enforce_equal(&node))?;

        Ok(new_nodes_vars)
    }
}

pub struct LeafExistance<F, FH, FHG>
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

impl<F, FH, FHG> LeafExistance<F, FH, FHG>
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
        Self {
            root,
            friend_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }

    pub fn synthesize(self, cs: ConstraintSystemRef<F>, leaf_var: FpVar<F>) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
        let cs = &cs;
        // alloc constants
        let inner_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc public inputs
        let root_var = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        // alloc witness var
        let friends_var = self.friend_nodes
            .into_iter()
            .map(|(is_left, node)| {
                let is_left = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                let node = FpVar::new_witness(cs.clone(), || Ok(node))?;

                Ok((is_left, node))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // leaf index
        let leaf_index = friends_var
            .iter()
            .map(|(is_left, _)| is_left.clone())
            .collect::<Vec<_>>();
        let leaf_index_var = Boolean::le_bits_to_fp_var(&leaf_index)?;

        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params_var,
            &friends_var,
            leaf_var,
        )?;
        // old root should restrain to input
        merkle_paths.last().unwrap().enforce_equal(&root_var)?;

        Ok((leaf_index_var, root_var))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
	use arkworks_utils::utils::common::{setup_params_x3_3, Curve, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, setup_params_x5_2};
    use bitvec::field::BitField;
    use bitvec::prelude::BitVec;

    use crate::{circuits::poseidon::PoseidonHasherGadget, vanilla::hasher::FieldHasher};
    use crate::vanilla::{hasher::poseidon::PoseidonHasher, merkle::gen_merkle_path};
    use super::{LeafExistance, AddNewLeaf};

    const HEIGHT: u8 = 28;

    fn get_random_merkle_friends(rng: &mut StdRng) -> Vec<(bool, Fr)> {
        let mut friend_nodes = vec![(bool::rand(rng), Fr::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            friend_nodes.push((bool::rand(rng), Fr::rand(rng)));
        }

        friend_nodes
    }

    #[test]
    fn test_leaf_existance() {
        let rng = &mut test_rng();
        let inner_params = setup_params_x3_3::<Fr>(Curve::Bn254);
        let leaf = Fr::rand(rng);
        let friend_nodes = get_random_merkle_friends(rng);
        let merkle_path = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &friend_nodes,
            leaf.clone(),
        ).unwrap();
        let root = merkle_path.last().unwrap().clone();
        let existance = LeafExistance::<_, _, PoseidonHasherGadget<Fr>>::new(
            root,
            friend_nodes,
            inner_params,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        _ = existance.synthesize(cs.clone(), leaf_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
        println!("instance: {}", cs.num_instance_variables());
        println!("witness: {}", cs.num_witness_variables());
    }

    #[test]
    fn test_add_new_leaf() {
        let rng = &mut test_rng();
        let params = setup_params_x3_3(Curve::Bn254);
        let friend_nodes = get_random_merkle_friends(rng);
        let index_iter = friend_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &params,
            &friend_nodes,
            PoseidonHasher::empty_hash(),
        ).unwrap();
        let old_root = update_nodes.last().unwrap().clone();
        let new_leaf = Fr::rand(rng);
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &params,
            &friend_nodes,
            new_leaf.clone(),
        ).unwrap();
        let add_new_leaf = AddNewLeaf::<_, _, PoseidonHasherGadget<Fr>>::new(
            new_leaf.clone(),
            index,
            friend_nodes,
            update_nodes,
            params,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let old_root_var = FpVar::new_input(cs.clone(), || Ok(old_root)).unwrap();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(new_leaf)).unwrap();
        _ = add_new_leaf.synthesize(cs.clone(), leaf_var, old_root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
        println!("instance: {}", cs.num_instance_variables());
        println!("witness: {}", cs.num_witness_variables());
    }

    #[test]
    fn test_params() {
        let params = setup_params_x5_2::<Fr>(Curve::Bn254);
        let round_keys = params.round_keys;
        let mds_matrix = params.mds_matrix;

        for key in round_keys {
            println!("    Fr::new(BigInteger::new({:?})),", key.0.0);
        }

        println!("");

        for matrix in mds_matrix {
            println!("    &[");
            for m in matrix {
                println!("        Fr::new(BigInteger::new({:?})),", m.0.0);
            }
            println!("    ],");
        }
    }
}