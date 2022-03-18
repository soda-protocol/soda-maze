use ark_crypto_primitives::Error;
use ark_ff::PrimeField;

use super::hasher::FieldHasher;

pub fn gen_merkle_path<F: PrimeField, FH: FieldHasher<F>, const HEIGHT: u8>(
    inner_params: &FH::Parameters,
    friends: &[(bool, F)],
    leaf_hash: F,
) -> Result<Vec<F>, Error> {
    assert_eq!(friends.len(), HEIGHT as usize);

    let mut previous = leaf_hash;
    friends
        .into_iter()
        .map(|(is_left, friend)| {
            previous = if *is_left {
                FH::hash_two(inner_params, friend.clone(), previous.clone())?
            } else {
                FH::hash_two(inner_params, previous.clone(), friend.clone())?
            };

            Ok(previous.clone())
        })
        .collect()
}
