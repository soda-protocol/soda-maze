use std::rc::Rc;
use ark_ec::models::twisted_edwards_extended::GroupAffine;
use soda_maze_lib::vanilla::hasher::poseidon::PoseidonHasher;
use soda_maze_lib::vanilla::deposit::DepositConstParams;
use soda_maze_lib::vanilla::withdraw::WithdrawConstParams;
use soda_maze_lib::vanilla::commit::CommitConstParams;

#[cfg(feature = "bn254")]
use ark_ed_on_bn254::{EdwardsParameters, Fq as Fr};
#[cfg(feature = "bls12-381")]
use ark_ed_on_bls12_381::{EdwardsParameters, Fq as Fr};

#[cfg(all(feature = "bn254", feature = "poseidon"))]
pub fn gen_deposit_const_params(
    height: usize,
    pubkey: Option<GroupAffine<EdwardsParameters>>,
) -> DepositConstParams<EdwardsParameters, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;

    DepositConstParams {
        leaf_params: Rc::new(get_poseidon_bn254_for_leaf()),
        inner_params: Rc::new(get_poseidon_bn254_for_merkle()),
        height,
        commit: pubkey.map(|pubkey| {
            CommitConstParams {
                nullifier_params: Rc::new(get_poseidon_bn254_for_nullifier()),
                pubkey,
            }
        }),
    }
}

#[cfg(all(feature = "bn254", feature = "poseidon"))]
pub fn gen_withdraw_const_params(
    height: usize,
    pubkey: Option<GroupAffine<EdwardsParameters>>,
) -> WithdrawConstParams<EdwardsParameters, PoseidonHasher<Fr>> {
    use soda_maze_lib::params::poseidon::*;
    
    let nullifier_params = Rc::new(get_poseidon_bn254_for_nullifier());
    WithdrawConstParams {
        nullifier_params: nullifier_params.clone(),
        leaf_params: Rc::new(get_poseidon_bn254_for_leaf()),
        inner_params: Rc::new(get_poseidon_bn254_for_merkle()),
        height,
        commit: pubkey.map(|pubkey| {
            CommitConstParams {
                nullifier_params,
                pubkey,
            }
        }),
    }
}