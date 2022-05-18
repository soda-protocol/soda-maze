use std::ops::{AddAssign, Mul, Add};
use num_traits::Zero;
use solana_program::program_error::ProgramError;

use crate::{bn::Field, error::MazeError, params::{hasher::PoseidonParameters, bn::Fr}};

fn apply_sbox(sbox: i8, elem: Fr) -> Result<Fr, ProgramError> {
    let res = match sbox {
        3 => elem * elem * elem,
        5 => {
            let sqr = elem.square();
            sqr.square().mul(elem)
        }
        17 => {
            let sqr = elem * elem;
            let quad = sqr * sqr;
            let eighth = quad * quad;
            let sixteenth = eighth * eighth;
            sixteenth * elem
        }
        // default to cubed
        _ => return Err(MazeError::PoseidonHashFailed.into()),
    };
    Ok(res)
}

pub fn poseidon_hash(
    params: &PoseidonParameters,
    mut state: Vec<Fr>,
) -> Result<Fr, ProgramError> {
    let nr = (params.full_rounds + params.partial_rounds) as usize;
    for r in 0..nr {
        state.iter_mut().enumerate().for_each(|(i, a)| {
            let c = params.round_keys[(r * (params.width as usize) + i)];
            a.add_assign(c);
        });

        let half_rounds = (params.full_rounds as usize) / 2;
        if r < half_rounds || r >= half_rounds + (params.partial_rounds as usize) {
            state
                .iter_mut()
                .try_for_each(|a| apply_sbox(params.sbox, *a).map(|f| *a = f))?;
        } else {
            state[0] = apply_sbox(params.sbox, state[0])?;
        }

        state = state
            .iter()
            .enumerate()
            .map(|(i, _)| {
                state.iter().enumerate().fold(Fr::zero(), |acc, (j, a)| {
                    let m = params.mds_matrix[i][j];
                    acc.add(m.mul(*a))
                })
            })
            .collect();
    }

    state.get(0).cloned().ok_or(MazeError::PoseidonHashFailed.into())
}
