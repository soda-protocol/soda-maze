use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::SynthesisError;
use arkworks_gadgets::mimc::constraints::MiMCParametersVar;

use crate::vanilla::hasher::mimc::MIMCHasher;
use super::FieldHasherGadget;

pub struct MIMCHasherGadget<F>(PhantomData<F>);

impl<F: PrimeField> FieldHasherGadget<F, MIMCHasher<F>> for MIMCHasherGadget<F> {
    type ParametersVar = MiMCParametersVar<F>;

    fn hash_gadget(params: &Self::ParametersVar, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        assert!(
            inputs.len() < params.num_inputs,
            "incorrect input length {:?} for width {:?}",
            inputs.len(),
            params.num_inputs,
        );

        let mut buffer = inputs.to_vec();
        buffer.resize(params.num_inputs, FpVar::zero());

        Self::mimc(params, buffer)
            .map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
    }
}

impl<F: PrimeField> MIMCHasherGadget<F> {
	fn mimc(
		parameters: &MiMCParametersVar<F>,
		state: Vec<FpVar<F>>,
	) -> Result<Vec<FpVar<F>>, SynthesisError> {
		assert!(state.len() == parameters.num_inputs);
		let mut l_out: FpVar<F> = FpVar::<F>::zero();
		let mut r_out: FpVar<F> = FpVar::<F>::zero();

		for (i, s) in state.iter().enumerate() {
			let l: FpVar<F>;
			let r: FpVar<F>;
			if i == 0 {
				l = s.clone();
				r = FpVar::<F>::zero();
			} else {
				l = l_out.clone() + s.clone();
				r = r_out.clone();
			}

			let res = Self::feistel(parameters, l, r)?;
			l_out = res[0].clone();
			r_out = res[1].clone();
		}

		let mut outs = vec![l_out.clone()];
		for _ in 0..parameters.num_outputs {
			let res = Self::feistel(parameters, l_out.clone(), r_out.clone())?;
			l_out = res[0].clone();
			r_out = res[1].clone();
			outs.push(l_out.clone());
		}

		Ok(outs)
	}

	fn feistel(
		parameters: &MiMCParametersVar<F>,
		left: FpVar<F>,
		right: FpVar<F>,
	) -> Result<[FpVar<F>; 2], SynthesisError> {
		let mut x_l = left;
		let mut x_r = right;
		let mut c: FpVar<F>;
		let mut t: FpVar<F>;
		let mut t2: FpVar<F>;
		let mut t4: FpVar<F>;
		for i in 0..parameters.rounds {
			c = if i == 0 || i == parameters.rounds - 1 {
				FpVar::<F>::zero()
			} else {
				parameters.round_keys[i - 1].clone()
			};
			t = if i == 0 {
				parameters.k.clone() + x_l.clone()
			} else {
				parameters.k.clone() + x_l.clone() + c
			};

			t2 = t.clone() * t.clone();
			t4 = t2.clone() * t2.clone();

			let temp_x_l = x_l.clone();
			let temp_x_r = x_r.clone();

			if i < parameters.rounds - 1 {
				x_l = if i == 0 { temp_x_r } else { temp_x_r + t4 * t };

				x_r = temp_x_l;
			} else {
				x_r = temp_x_r + t4 * t;
				x_l = temp_x_l;
			}
		}

		Ok([x_l, x_r])
	}
}
