use ark_ec::TEModelParameters;
use ark_std::{cmp::Ordering, rc::Rc};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::hasher::FieldHasher;
use super::{FieldHasherGadget, JubjubEncrypt};
use super::merkle::{AddNewLeaf, LeafExistance};
use super::uint64::Uint64;

pub struct WithdrawCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    nullifier_params: Rc<FH::Parameters>,
    leaf_params: Rc<FH::Parameters>,
    src_leaf_index: u64,
    dst_leaf_index: u64,
    balance: u64,
    withdraw_amount: u64,
    receiver: P::BaseField,
    nullifier: P::BaseField,
    secret: P::BaseField,
    prev_root: P::BaseField,
    dst_leaf: P::BaseField,
    src_proof: LeafExistance<P::BaseField, FH, FHG>,
    dst_proof: AddNewLeaf<P::BaseField, FH, FHG>,
    jubjub: Option<JubjubEncrypt<P, FH, FHG>>,
}

impl<P, FH, FHG> ConstraintSynthesizer<P::BaseField> for WithdrawCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<P::BaseField>) -> Result<()> {
        // alloc constant
        let nullifier_params = FHG::ParametersVar::new_constant(cs.clone(), self.nullifier_params)?;
        let leaf_params = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        
        // alloc input
        // withdraw amount bit size of 64 can verify in contract, so no need constrain in circuit
        let withdraw_amount = FpVar::new_input(cs.clone(), || Ok(P::BaseField::from(self.withdraw_amount)))?;
        let _receiver_input = FpVar::new_input(cs.clone(), || Ok(self.receiver))?;
        let nullifier_input = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        let dst_leaf_index = FpVar::new_input(cs.clone(), || Ok(P::BaseField::from(self.dst_leaf_index)))?;
        let dst_leaf_input = FpVar::new_input(cs.clone(), || Ok(self.dst_leaf))?;
        let prev_root = FpVar::new_input(cs.clone(), || Ok(self.prev_root))?;

        // alloc witness
        let src_leaf_index = FpVar::new_witness(cs.clone(), || Ok(P::BaseField::from(self.src_leaf_index)))?;
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
            &[dst_leaf_index.clone(), rest_amount, secret.clone()],
        )?;
        dst_leaf_input.enforce_equal(&dst_leaf)?;
        // gen add new leaf proof
        self.dst_proof.synthesize(cs.clone(), dst_leaf_index.clone(), dst_leaf, prev_root)?;

        // encrypt dst nullifier to commitment
        if let Some(jubjub) = self.jubjub {
            jubjub.synthesize(cs, dst_leaf_index, secret)?;
        }

        Ok(())
    }
}

impl<P, FH, FHG> WithdrawCircuit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nullifier_params: Rc<FH::Parameters>,
        leaf_params: Rc<FH::Parameters>,
        inner_params: Rc<FH::Parameters>,
        src_leaf_index: u64,
        dst_leaf_index: u64,
        balance: u64,
        withdraw_amount: u64,
        receiver: P::BaseField,
        nullifier: P::BaseField,
        prev_root: P::BaseField,
        dst_leaf: P::BaseField,
        update_nodes: Vec<P::BaseField>,
        secret: P::BaseField,
        src_neighbor_nodes: Vec<(bool, P::BaseField)>,
        dst_neighbor_nodes: Vec<(bool, P::BaseField)>,
        jubjub: Option<JubjubEncrypt<P, FH, FHG>>,
    ) -> Self {
        Self {
            nullifier_params,
            leaf_params,
            src_leaf_index,
            dst_leaf_index,
            balance,
            withdraw_amount,
            receiver,
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
            jubjub,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ed_on_bn254::{Fq as Fr, EdwardsParameters};
    use ark_std::{rc::Rc, test_rng, UniformRand, rand::Rng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::poseidon::PoseidonHasherGadget;
    use crate::vanilla::VanillaProof;
    use crate::vanilla::hasher::{poseidon::PoseidonHasher, FieldHasher};
    use crate::vanilla::withdraw::{WithdrawConstParams, WithdrawOriginInputs, WithdrawVanillaProof};
    use super::WithdrawCircuit;

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

    fn test_withdraw_inner<R: Rng + ?Sized>(rng: &mut R, balance: u64, withdraw_amount: u64) -> ConstraintSystemRef<Fr> {
        let nullifier_params = setup_params_x5_3(Curve::Bn254);
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        let inner_params = setup_params_x5_3(Curve::Bn254);
        // withdraw data
        let secret = Fr::rand(rng);
        let receiver = Fr::rand(rng);

        let (mut src_indexes, mut src_neighbor_nodes) = get_random_merkle_neighbors(rng);
        src_indexes[0] = false;
        src_neighbor_nodes[0] = PoseidonHasher::empty_hash();
        let src_leaf_index = BitVec::<u8>::from_iter(src_indexes).load_le::<u64>();
        let src_leaf = PoseidonHasher::hash(
            &leaf_params,
            &[Fr::from(src_leaf_index), Fr::from(balance), secret],
        ).unwrap();

        let mut dst_neighbor_nodes = src_neighbor_nodes.clone();
        dst_neighbor_nodes[0] = src_leaf;
        let dst_leaf_index = src_leaf_index + 1;

        let params = WithdrawConstParams::<EdwardsParameters, _> {
            nullifier_params: Rc::new(nullifier_params),
            leaf_params: Rc::new(leaf_params),
            inner_params: Rc::new(inner_params),
            height: HEIGHT as usize,
            jubjub: None,
        };
        let orig_in = WithdrawOriginInputs::<EdwardsParameters> {
            balance,
            withdraw_amount,
            src_leaf_index,
            dst_leaf_index,
            receiver,
            secret,
            src_neighbor_nodes,
            dst_neighbor_nodes,
            jubjub: None,
        };
        // generate vanilla proof
        let (pub_in, priv_in) = WithdrawVanillaProof::<_, PoseidonHasher<_>>::generate_vanilla_proof(
            &params,
            &orig_in,
        ).unwrap();

        let withdrawal = WithdrawCircuit::<EdwardsParameters, _, PoseidonHasherGadget<_>>::new(
            params.nullifier_params,
            params.leaf_params,
            params.inner_params,
            orig_in.src_leaf_index,
            orig_in.dst_leaf_index,
            orig_in.balance,
            orig_in.withdraw_amount,
            orig_in.receiver,
            pub_in.nullifier,
            pub_in.prev_root,
            pub_in.dst_leaf,
            pub_in.update_nodes,
            priv_in.secret,
            priv_in.src_neighbor_nodes,
            priv_in.dst_neighbor_nodes,
            None,
        );
        // generate snark proof
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
