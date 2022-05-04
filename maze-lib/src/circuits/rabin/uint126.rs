use ark_std::borrow::Borrow;
use ark_ff::PrimeField;
use ark_relations::{r1cs::{Namespace, SynthesisError, ConstraintSystemRef, Variable}, lc};
use ark_r1cs_std::{alloc::{AllocVar, AllocationMode}, R1CSVar, Assignment, boolean::{Boolean, AllocatedBool}};
use bitvec::{order::Lsb0, view::BitView};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;

#[derive(Clone, Debug)]
pub struct Uint126<F: PrimeField> {
    variable: Variable,
    cs: ConstraintSystemRef<F>,
    value: Option<u128>,
}

impl<F: PrimeField> R1CSVar<F> for Uint126<F> {
    type Value = u128;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.value.get()
    }
}

impl<F: PrimeField> AllocVar<u128, F> for Uint126<F> {
    fn new_variable<T: Borrow<u128>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = *f()?.borrow();
        assert!(v < 1u128 << 126);

        if mode == AllocationMode::Constant {
            let lc = cs.new_lc(lc!() + (F::from(v), Variable::One))?;
            Ok(Self::new(Some(v), lc, cs))
        } else {
            let mut value = None;
            let value_generator = || {
                value = Some(v);
                Ok(F::from(v))
            };
            let variable = if mode == AllocationMode::Input {
                cs.new_input_variable(value_generator)?
            } else {
                cs.new_witness_variable(value_generator)?
            };

            // bits constrain
            let mut coeff = F::one();
            let mut lc = lc!();
            v.view_bits::<Lsb0>()
                .into_iter()
                .take(126)
                .try_for_each(|bit| {
                    let var = AllocatedBool::new_witness(cs.clone(), || Ok(bit))?;
                    lc += (coeff, var);
                    coeff.double_in_place();

                    Ok(())
                })?;
    
            cs.enforce_constraint(
                lc!() + variable,
                lc!() + Variable::One,
                lc,
            )?;

            Ok(Self::new(value, variable, cs))
        }
    }
}

impl<F: PrimeField> Uint126<F> {
    pub fn new(value: Option<u128>, variable: Variable, cs: ConstraintSystemRef<F>) -> Self {
        Self { variable, cs, value }
    }

    pub fn zero(cs: ConstraintSystemRef<F>) -> Self {
        Self {
            variable: Variable::Zero,
            cs,
            value: Some(0),
        }
    }

    pub fn mul_constant(&self, other: u128) -> Result<(Self, Self), SynthesisError> {
        assert!(other < 1u128 << 126);
        
        let (hi, lo, hi_var, lo_var) = match other {
            0 => (Some(0), Some(0), Variable::Zero, Variable::Zero),
            1 => (Some(0), self.value, Variable::Zero, self.variable),
            _ => {
                let base = BigUint::from(1u128 << 126);
                let product = F::from(self.value()?) * F::from(other);
                let (hi, lo) = BigUint::from(product.into_repr()).div_rem(&base);
                let hi_var = self.cs.new_witness_variable(|| Ok(F::from(hi)))?;
                let lo_var = self.cs.new_witness_variable(|| Ok(F::from(lo)))?;

                self.cs.enforce_constraint(
                    lc!() + self.variable,
                    lc!() + (F::from(other), Variable::One),
                    lc!() + (F::from(base), hi_var) + lo_var,
                )?;

                (hi.to_u128(), lo.to_u128(), hi_var, lo_var)
            }
        };

        let hi = Self::new(hi, hi_var, self.cs.clone());
        let lo = Self::new(lo, lo_var, self.cs.clone());
        Ok((hi, lo))
    }

    pub fn add_with_carry(&self, other: &Self, old_carry: &Self) -> Result<(Self, Self), SynthesisError> {
        let (
            new_carry,
            sum,
            new_carry_var,
            sum_var,
        ) = if self.variable == Variable::Zero && other.variable == Variable::Zero {
            (Some(0), old_carry.value, Variable::Zero, old_carry.variable)
        } else {
            let base = BigUint::from(1u128 << 126);
            let sum = F::from(self.value()?) + F::from(other.value()?) + F::from(old_carry.value()?);
            let (new_carry, sum) = BigUint::from(sum.into_repr()).div_rem(&base);
        
            let new_carry_var = self.cs.new_witness_variable(|| Ok(F::from(new_carry)))?;
            let sum_var = self.cs.new_witness_variable(|| Ok(F::from(sum)))?;
    
            self.cs.enforce_constraint(
                lc!() + self.variable + other.variable + old_carry.variable,
                lc!() + Variable::One,
                lc!() + (F::from(base), new_carry_var) + sum_var,
            )?;

            (new_carry.to_u128(), sum.to_u128(), new_carry_var, sum_var)
        };

        let new_carry_var = Self::new(new_carry, new_carry_var, self.cs.clone());
        let sum = Self::new(sum, sum_var, self.cs.clone());
        Ok((new_carry_var, sum))
    }

    pub fn add_no_carry(&self, other: &Self) -> Result<(Self, Self), SynthesisError> {
        let (
            new_carry,
            sum,
            new_carry_var,
            sum_var,
        ) = if self.variable == Variable::Zero {
            (Some(0), other.value, Variable::Zero, other.variable)
        } else if other.variable == Variable::Zero {
            (Some(0), self.value, Variable::Zero, self.variable)
        } else {
            let base = BigUint::from(1u128 << 126);
            let sum = F::from(self.value()?) + F::from(other.value()?);
            let (new_carry, sum) = BigUint::from(sum.into_repr()).div_rem(&base);
        
            let new_carry_var = self.cs.new_witness_variable(|| Ok(F::from(new_carry)))?;
            let sum_var = self.cs.new_witness_variable(|| Ok(F::from(sum)))?;
    
            self.cs.enforce_constraint(
                lc!() + self.variable + other.variable,
                lc!() + Variable::One,
                lc!() + (F::from(base), new_carry_var) + sum_var,
            )?;

            (new_carry.to_u128(), sum.to_u128(), new_carry_var, sum_var)
        };

        let new_carry_var = Self::new(new_carry, new_carry_var, self.cs.clone());
        let sum = Self::new(sum, sum_var, self.cs.clone());
        Ok((new_carry_var, sum))
    }

    pub fn add_carry(&self, carry: &Self) -> Result<Self, SynthesisError> {
        let value = self.value()? + carry.value()?;
        let sum_var = self.cs.new_lc(lc!() + self.variable + carry.variable)?;

        let sum = Self::new(Some(value), sum_var, self.cs.clone());
        Ok(sum)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, ConstraintSynthesizer};
	use arkworks_utils::utils::common::{Curve, setup_params_x5_3, setup_params_x5_4, setup_params_x5_2};

    #[cfg(test)]
    fn test_mul_constant() {
        
    }
}