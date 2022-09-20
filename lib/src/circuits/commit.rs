use ark_std::{marker::PhantomData, rc::Rc};
use ark_ff::{PrimeField, FpParameters};
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ec::{TEModelParameters, twisted_edwards_extended::{GroupAffine, GroupProjective}};
use ark_r1cs_std::ToBitsGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::{curves::twisted_edwards::AffineVar, CurveVar};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::vanilla::hasher::FieldHasher;
use super::FieldHasherGadget;

pub struct Commit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    nullifier_params: Rc<FH::Parameters>,
    pubkey: GroupAffine<P>,
    nonce_bits: Vec<bool>,
    commitment: (GroupAffine<P>, GroupAffine<P>),
    _p: PhantomData<FHG>,
}

impl<P, FH, FHG> Commit<P, FH, FHG>
where
    P: TEModelParameters,
    FH: FieldHasher<P::BaseField>,
    FHG: FieldHasherGadget<P::BaseField, FH>,
    P::BaseField: PrimeField,
{
    pub fn new(
        nullifier_params: Rc<FH::Parameters>,
        pubkey: GroupAffine<P>,
        nonce_bits: Vec<bool>,
        commitment: (GroupAffine<P>, GroupAffine<P>),
    ) -> Self {
        Self {
            nullifier_params,
            pubkey,
            nonce_bits,
            commitment,
            _p: Default::default(),
        }
    }

    pub fn synthesize(
        self,
        cs: ConstraintSystemRef<P::BaseField>,
        leaf_index: FpVar<P::BaseField>,
        secret: FpVar<P::BaseField>,
    ) -> Result<(), SynthesisError>
    where
        P::BaseField: PrimeField,
    {
        let scalar_bits = <<P::ScalarField as PrimeField>::Params as FpParameters>::CAPACITY as usize;

        // alloc constant
        let nullifier_params = FHG::ParametersVar::new_constant(
            cs.clone(),
            self.nullifier_params,
        )?;
        // Note: generator and pubkey is no need to define constant here.

        // allocate public inputs
        let commitment_0 = AffineVar::<_, FpVar<P::BaseField>>::new_input(
            cs.clone(),
            || Ok(self.commitment.0),
        )?;
        let commitment_1 = AffineVar::<_, FpVar<P::BaseField>>::new_input(
            cs.clone(),
            || Ok(self.commitment.1),
        )?;

        // allocate witness
        let nonce = self.nonce_bits
            .into_iter()
            .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
            .collect::<Result<Vec<_>, _>>()?;

        // hash for nullifier
        let nullifier = FHG::hash_gadget(&nullifier_params, &[leaf_index, secret])?;
        let mut nullifier_bits = nullifier.to_bits_le()?;
        nullifier_bits.truncate(scalar_bits);

        // encrypt nullifier by `Elgamal` algorithm.
        // compute commitment_0 = nonce * G
        let mut base = GroupProjective::prime_subgroup_generator();
        let mut bases = Vec::with_capacity(scalar_bits);
        for _ in 0..scalar_bits {
            bases.push(base);
            base.double_in_place();
        }

        let mut point = AffineVar::zero();
        point.precomputed_base_scalar_mul_le(nonce.iter().zip(bases.iter()))?;
        // constrain point = commitment_0
        point.enforce_equal(&commitment_0)?;

        // compute commitment_1 = nullifier * G + nonce * P
        point = AffineVar::zero();
        point.precomputed_base_scalar_mul_le(nullifier_bits.into_iter().zip(bases.iter()))?;

        base = self.pubkey.into_projective();
        for b in bases.iter_mut() {
            *b = base;
            base.double_in_place();
        }
        point.precomputed_base_scalar_mul_le(nonce.iter().zip(bases.iter()))?;
        // constrain point = commitment_1
        point.enforce_equal(&commitment_1)?;

        Ok(())
    }
} 

#[cfg(test)]
mod tests {
    use ark_ec::{twisted_edwards_extended::GroupProjective, ProjectiveCurve};
    use ark_ed_on_bn254::{Fq, Fr, EdwardsParameters};
    use ark_ff::PrimeField;
    use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use arkworks_utils::utils::common::{Curve, setup_params_x5_3};
    use ark_std::{rc::Rc, test_rng, UniformRand};

    use crate::vanilla::commit::*;
    use crate::vanilla::hasher::poseidon::PoseidonHasher;
    use crate::circuits::poseidon::PoseidonHasherGadget;
    use super::Commit;

    #[test]
    fn test_commit() {
        let rng = &mut test_rng();
        // gen keypair
        let generator = GroupProjective::<EdwardsParameters>::prime_subgroup_generator();
        let private: <Fr as PrimeField>::BigInt = Fr::rand(rng).into();
        let pubkey = generator.mul(private);

        // nullifier
        let nullifier_params = setup_params_x5_3::<Fq>(Curve::Bn254);
        let leaf_index = u64::rand(rng);
        let secret = Fq::rand(rng);

        // gen params
        let params = CommitConstParams::<_, PoseidonHasher<_>> {
            nullifier_params: Rc::new(nullifier_params),
            pubkey: pubkey.into_affine(),
        };

        // gen origin inputs
        let orig_in = CommitOriginInputs {
            nonce: Fr::rand(rng),
        };

        // gen vanilla proof
        let (pub_in, priv_in) = generate_vanilla_proof(
            &params,
            &orig_in,
            leaf_index,
            secret,
        ).unwrap();
        
        // gen snark proof
        let cs = ConstraintSystem::new_ref();
        let leaf_index = FpVar::new_input(cs.clone(), || Ok(Fq::from(leaf_index))).unwrap();
        let secret = FpVar::new_witness(cs.clone(), || Ok(secret)).unwrap();
        let commit = Commit::<_, _, PoseidonHasherGadget<_>>::new(
            params.nullifier_params,
            params.pubkey,
            priv_in.nonce_bits,
            pub_in.commitment,
        );
        commit.synthesize(cs.clone(), leaf_index, secret).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}