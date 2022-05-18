use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_crypto_primitives::Error;
use arkworks_utils::mimc::{MiMCParameters, MiMCError};

use super::FieldHasher;

#[derive(Clone)]
pub struct MIMCHasher<F>(PhantomData<F>);

impl<F: PrimeField> FieldHasher<F> for MIMCHasher<F> {
    type Parameters = MiMCParameters<F>;

    fn empty_hash() -> F {
        F::zero()
    }

    fn hash(params: &Self::Parameters, inputs: &[F]) -> Result<F, Error> {
        assert!(
            inputs.len() < params.num_inputs,
            "incorrect input length {:?} for width {:?}",
            inputs.len(),
            params.num_inputs,
        );

        let mut buffer = inputs.to_vec();
        buffer.resize(params.num_inputs, F::zero());

		let result = Self::mimc(params, buffer)?
            .get(0)
            .cloned()
            .ok_or(MiMCError::InvalidInputs)?;

        Ok(result)
    }
}

impl<F: PrimeField> MIMCHasher<F> {
    fn mimc(params: &MiMCParameters<F>, state: Vec<F>) -> Result<Vec<F>, MiMCError> {
		assert!(state.len() == params.num_inputs);
		let mut l_out: F = F::zero();
		let mut r_out: F = F::zero();
		for (i, s) in state.iter().enumerate() {
			let l: F;
			let r: F;
			if i == 0 {
				l = *s;
				r = F::zero();
			} else {
				l = l_out + s;
				r = r_out;
			}

			let res = Self::feistel(params, l, r)?;
			l_out = res[0];
			r_out = res[1];
		}

		let mut outs = vec![l_out];
		for _ in 0..params.num_outputs {
			let res = Self::feistel(params, l_out, r_out)?;
			l_out = res[0];
			r_out = res[1];
			outs.push(l_out);
		}

		Ok(outs)
	}

	fn feistel(params: &MiMCParameters<F>, left: F, right: F) -> Result<[F; 2], MiMCError> {
		let mut x_l = left;
		let mut x_r = right;
		let mut c: F;
		let mut t: F;
		let mut t2: F;
		let mut t4: F;
		for i in 0..params.rounds {
			c = if i == 0 || i == params.rounds - 1 {
				F::zero()
			} else {
				params.round_keys[i - 1]
			};
			t = if i == 0 {
				params.k + x_l
			} else {
				params.k + x_l + c
			};

			t2 = t * t;
			t4 = t2 * t2;

			let temp_x_l = x_l;
			let temp_x_r = x_r;

			if i < params.rounds - 1 {
				x_l = if i == 0 {
					temp_x_r
				} else {
					temp_x_r + (t4 * t)
				};

				x_r = temp_x_l;
			} else {
				x_r = temp_x_r + (t4 * t);
				x_l = temp_x_l;
			}
		}

		Ok([x_l, x_r])
	}
}