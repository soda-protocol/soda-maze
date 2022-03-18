mod proof;

pub use proof::*;

use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, select::CondSelectGadget, fields::fp::FpVar};
use ark_relations::r1cs::SynthesisError;

use crate::primitives::hasher::FieldHasher;
use super::hasher::FieldHasherGadget;

pub fn gen_merkle_path_gadget<F, FH, FHG, const HEIGHT: u8>(
    inner_params: &FHG::ParametersVar,
    friends: &[(Boolean<F>, FpVar<F>)],
    leaf_hash: FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError>
where
    F: PrimeField,
    FH: FieldHasher<F>,
    FHG: FieldHasherGadget<F, FH>,
{
    assert_eq!(friends.len(), HEIGHT as usize);

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

// pub fn gen_merkle_path_gadget<F, P, HG, LHG, H>(
//     inner_params: &HG::ParametersVar,
//     friends: &[(Boolean<F>, NodeVar<F, P, HG, LHG>)],
//     leaf_hash: NodeVar<F, P, HG, LHG>,
// ) -> Result<Vec<NodeVar<F, P, HG, LHG>>, SynthesisError>
// where
//     F: PrimeField,
//     P: Config,
//     HG: CRHGadget<P::H, F>,
//     LHG: CRHGadget<P::LeafH, F>,
//     H: HasherGadget<F, P, HG, LHG>,
// {
//     assert_eq!(friends.len(), P::HEIGHT as usize);

//     // Check levels between leaf level and root.
//     let mut previous_hash = leaf_hash;
//     friends
//         .iter()
//         .map(|(is_left, friend_hash)| {
//             let left_hash = NodeVar::conditionally_select(
//                 is_left,
//                 friend_hash,
//                 &previous_hash,
//             )?;
//             let right_hash = NodeVar::conditionally_select(
//                 is_left,
//                 &previous_hash,
//                 friend_hash,
//             )?;

//             previous_hash = H::hash_2(
//                 inner_params,
//                 &left_hash,
//                 &right_hash,
//             )?;

//             Ok(previous_hash.clone())
//         })
//         .collect()
// }
