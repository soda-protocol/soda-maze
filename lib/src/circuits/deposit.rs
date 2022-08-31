use ark_ec::TEModelParameters;
use ark_std::rc::Rc;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::hasher::FieldHasher;
use super::merkle::AddNewLeaf;
use super::{FieldHasherGadget, Commit};

pub struct DepositCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    leaf_params: Rc<FH::Parameters>,
    deposit_amount: u64,
    leaf_index: u64,
    leaf: P::BaseField,
    prev_root: P::BaseField,
    secret: P::BaseField,
    proof: AddNewLeaf<P::BaseField, FH, FHG>,
    commit: Option<Commit<P, FH, FHG>>,
}

impl<P, FH, FHG> ConstraintSynthesizer<P::BaseField> for DepositCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<P::BaseField>) -> Result<()> {
        // alloc constant
        let leaf_params = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        
        // alloc input
        // amount bit size of 64 can verify in contract, so no need constrain in circuit
        let deposit_amount = FpVar::new_input(cs.clone(), || Ok(P::BaseField::from(self.deposit_amount)))?;
        let leaf_index = FpVar::new_input(cs.clone(), || Ok(P::BaseField::from(self.leaf_index)))?;
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

        // commit commitment
        if let Some(commit) = self.commit {
            commit.synthesize(cs, leaf_index, secret)?;
        }

        Ok(())
    }
}

impl<P, FH, FHG> DepositCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        leaf_params: Rc<FH::Parameters>,
        inner_params: Rc<FH::Parameters>,
        deposit_amount: u64,
        leaf_index: u64,
        leaf: P::BaseField,
        prev_root: P::BaseField,
        update_nodes: Vec<P::BaseField>,
        secret: P::BaseField,
        neighbor_nodes: Vec<(bool, P::BaseField)>,
        commit: Option<Commit<P, FH, FHG>>,
    ) -> Self {
        Self {
            leaf_params,
            deposit_amount,
            leaf_index,
            leaf,
            prev_root,
            secret,
            proof: AddNewLeaf::new(
                neighbor_nodes,
                update_nodes,
                inner_params,
            ),
            commit,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ed_on_bn254::{Fq as Fr, EdwardsParameters};
    use ark_std::{rc::Rc, test_rng, UniformRand, rand::Rng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::hasher::poseidon::PoseidonHasherGadget;
    use crate::vanilla::VanillaProof;
    use crate::vanilla::deposit::{DepositConstParams, DepositOriginInputs, DepositVanillaProof};
    use crate::vanilla::hasher::poseidon::PoseidonHasher;
    use super::DepositCircuit;

    const HEIGHT: u8 = 24;

    fn get_random_merkle_neighbors<R: Rng + ?Sized>(rng: &mut R) -> (Vec<bool>, Vec<Fr>) {
        let mut neighbor_nodes = vec![Fr::rand(rng)];
        let mut indexes = vec![bool::rand(rng)];
        for _ in 0..(HEIGHT - 1) {
            indexes.push(bool::rand(rng));
            neighbor_nodes.push(Fr::rand(rng));
        }

        (indexes, neighbor_nodes)
    }

    #[test]
    fn test_deposit() {
        let rng = &mut test_rng();
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        let inner_params = setup_params_x5_3::<Fr>(Curve::Bn254);
        // deposit data
        let deposit_amount = u64::rand(rng);
        let secret = Fr::rand(rng);

        let (indexes, neighbor_nodes) = get_random_merkle_neighbors(rng);
        let leaf_index = BitVec::<u8>::from_iter(indexes).load_le::<u64>();
        
        let params = DepositConstParams::<EdwardsParameters, _> {
            leaf_params: Rc::new(leaf_params),
            inner_params: Rc::new(inner_params),
            height: HEIGHT as usize,
            commit: None,
        };
        let orig_in = DepositOriginInputs {
            leaf_index,
            deposit_amount,
            secret,
            neighbor_nodes,
            commit: None,
        };
        // generate vanilla proof
        let (pub_in, priv_in) = DepositVanillaProof::<_, PoseidonHasher<_>>::generate_vanilla_proof(
            &params,
            &orig_in,
        ).unwrap();

        let deposit = DepositCircuit::<EdwardsParameters, _, PoseidonHasherGadget<_>>::new(
            params.leaf_params,
            params.inner_params,
            pub_in.deposit_amount,
            pub_in.leaf_index,
            pub_in.leaf,
            pub_in.prev_root,
            pub_in.update_nodes,
            priv_in.secret,
            priv_in.neighbor_nodes,
            None,
        );
        // generate snark proof
        let cs = ConstraintSystem::new_ref();
        deposit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("constraints: {}", cs.num_constraints());
    }
}