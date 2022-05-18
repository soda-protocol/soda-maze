use ark_std::{cmp::Ordering, rc::Rc};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, Result};

use crate::vanilla::{array::Pubkey, hasher::FieldHasher};
use super::{FieldHasherGadget, RabinEncryption};
use super::merkle::{AddNewLeaf, LeafExistance};
use super::uint64::Uint64;

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
    secret: F,
    secret_params: Rc<FH::Parameters>,
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
        let secret_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.secret_params)?;
        let leaf_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.leaf_params)?;
        let nullifier_params_var = FHG::ParametersVar::new_constant(cs.clone(), self.nullifier_params)?;
        // alloc input
        let mint_var = FpVar::new_input(cs.clone(), || Ok(self.mint.to_field_element::<F>()))?;
        // withdraw amount bit size of 64 can verify in contract, so no need constrain in circuit
        let withdraw_amount_var = FpVar::new_input(cs.clone(), || Ok(F::from(self.withdraw_amount)))?;
        let input_nullifier_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        // alloc witness
        let deposit_amount_var = Uint64::new_witness(cs.clone(), || Ok(self.deposit_amount))?;
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        // restrain withdraw amount is less and equal than deposit amount
        let deposit_amount_var = deposit_amount_var.fp_var().clone();
        deposit_amount_var.enforce_cmp_unchecked(
            &withdraw_amount_var,
            Ordering::Greater,
            true,
        )?;
        let rest_amount_var = &deposit_amount_var - withdraw_amount_var;

        // hash secret
        let secret_hash_var = FHG::hash_gadget(
            &secret_params_var,
            &[secret_var.clone()],
        )?;

        // hash leaf: hash(pubkey | deposit_amount | secret_hash)
        let leaf_var = FHG::hash_gadget(
            &leaf_params_var,
            &[mint_var.clone(), deposit_amount_var, secret_hash_var.clone()],
        )?;
        // gen existance proof
        let (leaf_index_var, old_root_var) = self.proof_1.synthesize(cs.clone(), leaf_var.clone())?;

        // rabin encrytion for leaf
        if let Some(rabin_encrytion) = self.rabin_encrytion {
            rabin_encrytion.synthesize(cs.clone(), leaf_index_var.clone(), leaf_var)?;
        }

        // gen nullifier
        let nullifier_var = FHG::hash_gadget(
            &nullifier_params_var,
            &[leaf_index_var, secret_var],
        )?;
        nullifier_var.enforce_equal(&input_nullifier_var)?;

        // hash new back deposit data leaf: hash(pubkey | rest_amount | secret_hash)
        let leaf_var = FHG::hash_gadget(
            &leaf_params_var,
            &[mint_var, rest_amount_var, secret_hash_var],
        )?;
        // gen add new leaf proof
        self.proof_2.synthesize(cs.clone(), leaf_var, old_root_var)?;

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
        secret: F,
        leaf_index_2: u64,
        leaf_2: F,
        old_root: F,
        friend_nodes_1: Vec<(bool, F)>,
        friend_nodes_2: Vec<(bool, F)>,
        update_nodes: Vec<F>,
        secret_params: FH::Parameters,
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
            secret,
            secret_params: Rc::new(secret_params),
            nullifier_params: Rc::new(nullifier_params),
            leaf_params: Rc::new(leaf_params),
            proof_1: LeafExistance::new(
                old_root,
                friend_nodes_1,
                inner_params.clone(),
            ),
            proof_2: AddNewLeaf::new(
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
	use arkworks_utils::utils::common::{Curve, setup_params_x3_3, setup_params_x5_2, setup_params_x5_3, setup_params_x5_4};
    use bitvec::{prelude::BitVec, field::BitField};

    use crate::circuits::poseidon::PoseidonHasherGadget;
    use crate::vanilla::{array::Pubkey, merkle::gen_merkle_path};
    use crate::vanilla::hasher::{poseidon::PoseidonHasher, FieldHasher};
    use super::WithdrawCircuit;

    const HEIGHT: u8 = 24;

    fn get_random_merkle_friends(rng: &mut StdRng) -> Vec<(bool, Fr)> {
        let mut friend_nodes = vec![(bool::rand(rng), Fr::rand(rng))];
        for _ in 0..(HEIGHT - 1) {
            friend_nodes.push((bool::rand(rng), Fr::rand(rng)));
        }

        friend_nodes
    }

    fn test_withdraw_inner(rng: &mut StdRng, deposit_amount: u64, withdraw_amount: u64) -> ConstraintSystemRef<Fr> {
        let secret_params = setup_params_x5_2(Curve::Bn254);
        let nullifier_params = setup_params_x5_3(Curve::Bn254);
        let leaf_params = setup_params_x5_4::<Fr>(Curve::Bn254);
        let inner_params = setup_params_x3_3(Curve::Bn254);
        // deposit data
        let mint = Pubkey::new(<[u8; 32]>::rand(rng));
        let secret = Fr::rand(rng);
        let secret_hash = PoseidonHasher::hash(&secret_params, &[secret]).unwrap();
        let rest_amount = deposit_amount.saturating_sub(withdraw_amount);

        let mint_fp = mint.to_field_element::<Fr>();
        let leaf_1 = PoseidonHasher::hash(
            &leaf_params,
            &[mint_fp, Fr::from(deposit_amount), secret_hash],
        ).unwrap();
        let leaf_2 = PoseidonHasher::hash(
            &leaf_params,
            &[mint_fp, Fr::from(rest_amount), secret_hash],
        ).unwrap();

        let mut friend_nodes_1 = get_random_merkle_friends(rng);
        friend_nodes_1[0] = (false, PoseidonHasher::empty_hash());
        let index_iter = friend_nodes_1.iter().map(|(is_left, _)| is_left).collect::<Vec<_>>();
        let index_1 = BitVec::<u8>::from_iter(index_iter).load_le::<u64>();
        let mut friend_nodes_2 = friend_nodes_1.clone();
        friend_nodes_2[0] = (true, leaf_1);
        let index_2 = index_1 + 1;
        let nullifier = PoseidonHasher::hash(
            &nullifier_params,
            &[Fr::from(index_1), secret],
        ).unwrap();

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

        let withdrawal = WithdrawCircuit::<_, PoseidonHasher<Fr>, PoseidonHasherGadget<Fr>>::new(
            mint,
            withdraw_amount,
            deposit_amount,
            nullifier,
            secret,
            index_2,
            leaf_2,
            old_root,
            friend_nodes_1,
            friend_nodes_2,
            update_nodes,
            secret_params,
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
