use ark_std::{rc::Rc, marker::PhantomData};
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, boolean::Boolean, alloc::AllocVar, select::CondSelectGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystemRef, Result};

use crate::vanilla::hasher::FieldHasher;
use super::FieldHasherGadget;

fn gen_merkle_path_gadget<F, FH, FHG>(
    inner_params: &FHG::ParametersVar,
    neighbors: &[(Boolean<F>, FpVar<F>)],
    leaf_hash: FpVar<F>,
) -> Result<Vec<FpVar<F>>>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    // Check levels between leaf level and root.
    let mut previous_hash = leaf_hash;
    neighbors
        .iter()
        .map(|(is_left, neighbor_hash)| {
            let left_hash = FpVar::conditionally_select(
                is_left,
                neighbor_hash,
                &previous_hash,
            )?;
            let right_hash = FpVar::conditionally_select(
                is_left,
                &previous_hash,
                neighbor_hash,
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
    neighbor_nodes: Vec<(bool, F)>,
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
        neighbor_nodes: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        inner_params: FH::Parameters,
    ) -> Self {
        assert_eq!(neighbor_nodes.len(), update_nodes.len(), "neighbor nodes length should equals to update nodes length");

        Self {
            neighbor_nodes,
            update_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }
    
    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<F>,
        leaf_index: FpVar<F>,
        leaf: FpVar<F>,
        root: FpVar<F>,
    ) -> Result<()> {
        let ref cs = cs;
        // alloc constants
        let inner_params = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc public var
        let update_nodes = self.update_nodes
            .into_iter()
            .map(|node| FpVar::new_input(cs.clone(), || Ok(node)))
            .collect::<Result<Vec<_>>>()?;
        // alloc witness var
        let neighbors = self.neighbor_nodes
            .into_iter()
            .map(|(is_left, node)| {
                let is_left = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                // neighbor node can be alloc as public, but no need to do it here
                let node = FpVar::new_witness(cs.clone(), || Ok(node))?;

                Ok((is_left, node))
            })
            .collect::<Result<Vec<_>>>()?;

        // leaf index constrain
        let index_array = neighbors
            .iter()
            .map(|(is_left, _)| is_left.clone())
            .collect::<Vec<_>>();
        leaf_index.enforce_equal(&Boolean::le_bits_to_fp_var(&index_array)?)?;
        
        // old root constrain
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params,
            &neighbors,
            FHG::empty_hash_var(),
        )?;
        merkle_paths.last().unwrap().enforce_equal(&root)?;

        // leaf change
        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params,
            &neighbors,
            leaf,
        )?;
        // new paths should restrain to input
        update_nodes
            .into_iter()
            .zip(merkle_paths)
            .try_for_each(|(input_node, node)| input_node.enforce_equal(&node))
    }
}

pub struct LeafExistance<F, FH, FHG>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    neighbor_nodes: Vec<(bool, F)>,
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
        neighbor_nodes: Vec<(bool, F)>,
        inner_params: FH::Parameters,
    ) -> Self {
        Self {
            neighbor_nodes,
            inner_params: Rc::new(inner_params),
            _h: Default::default(),
        }
    }

    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<F>,
        leaf_index: FpVar<F>,
        leaf: FpVar<F>,
        root: FpVar<F>,
    ) -> Result<()> {
        let ref cs = cs;
        // alloc constants
        let inner_params = FHG::ParametersVar::new_constant(cs.clone(), self.inner_params)?;
        // alloc witness var
        let neighbors = self.neighbor_nodes
            .into_iter()
            .map(|(is_left, node)| {
                let is_left = Boolean::new_witness(cs.clone(), || Ok(is_left))?;
                let node = FpVar::new_witness(cs.clone(), || Ok(node))?;

                Ok((is_left, node))
            })
            .collect::<Result<Vec<_>>>()?;

        // leaf index
        let index_array = neighbors
            .iter()
            .map(|(is_left, _)| is_left.clone())
            .collect::<Vec<_>>();
        leaf_index.enforce_equal(&Boolean::le_bits_to_fp_var(&index_array)?)?;

        let merkle_paths = gen_merkle_path_gadget::<_, _, FHG>(
            &inner_params,
            &neighbors,
            leaf,
        )?;
        // old root should restrain to input
        merkle_paths.last().unwrap().enforce_equal(&root)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
	use arkworks_utils::utils::common::{setup_params_x3_3, Curve};
    use bitvec::field::BitField;
    use bitvec::prelude::BitVec;

    use crate::{circuits::poseidon::PoseidonHasherGadget, vanilla::hasher::FieldHasher};
    use crate::vanilla::{hasher::poseidon::PoseidonHasher, merkle::gen_merkle_path};
    use super::{LeafExistance, AddNewLeaf};

    const HEIGHT: u8 = 27;

    fn get_random_merkle_neighbors(rng: &mut StdRng) -> Vec<(bool, Fr)> {
        let mut neighbor_nodes = vec![(bool::rand(rng), Fr::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            neighbor_nodes.push((bool::rand(rng), Fr::rand(rng)));
        }

        neighbor_nodes
    }

    #[test]
    fn test_leaf_existance() {
        let rng = &mut test_rng();
        let inner_params = setup_params_x3_3::<Fr>(Curve::Bn254);
        let leaf = Fr::rand(rng);
        let neighbor_nodes = get_random_merkle_neighbors(rng);
        let index_iter = neighbor_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();
        let merkle_path = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &inner_params,
            &neighbor_nodes,
            leaf.clone(),
        ).unwrap();
        let root = merkle_path.last().unwrap().clone();
        let existance = LeafExistance::<_, _, PoseidonHasherGadget<Fr>>::new(
            neighbor_nodes,
            inner_params,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let index_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(index))).unwrap();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();
        _ = existance.synthesize(cs.clone(), index_var, leaf_var, root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_add_new_leaf() {
        let rng = &mut test_rng();
        let params = setup_params_x3_3(Curve::Bn254);
        let neighbor_nodes = get_random_merkle_neighbors(rng);
        let index_iter = neighbor_nodes.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index = BitVec::<u8>::from_iter(index_iter)
            .load_le::<u64>();
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &params,
            &neighbor_nodes,
            PoseidonHasher::empty_hash(),
        ).unwrap();
        let prev_root = update_nodes.last().unwrap().clone();
        let new_leaf = Fr::rand(rng);
        let update_nodes = gen_merkle_path::<_, PoseidonHasher<Fr>>(
            &params,
            &neighbor_nodes,
            new_leaf.clone(),
        ).unwrap();
        let add_new_leaf = AddNewLeaf::<_, _, PoseidonHasherGadget<Fr>>::new(
            neighbor_nodes,
            update_nodes,
            params,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        let prev_root_var = FpVar::new_input(cs.clone(), || Ok(prev_root)).unwrap();
        let leaf_index_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(index))).unwrap();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(new_leaf)).unwrap();
        _ = add_new_leaf.synthesize(cs.clone(), leaf_index_var, leaf_var, prev_root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
    }
}