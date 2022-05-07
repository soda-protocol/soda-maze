use ark_ff::{PrimeField, FpParameters};
use ark_relations::{r1cs::{Namespace, SynthesisError, ConstraintSystemRef, Variable}, lc};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar, Assignment, boolean::{AllocatedBool, Boolean}, fields::fp::FpVar};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;

#[derive(Debug)]
pub struct GeneralUint<F: PrimeField, const BIT: u32> {
    variable: Variable,
    cs: ConstraintSystemRef<F>,
    value: Option<u128>,
}

impl<F: PrimeField, const BIT: u32> Clone for GeneralUint<F, BIT> {
    fn clone(&self) -> Self {
        Self {
            variable: self.variable.clone(),
            cs: self.cs.clone(),
            value: self.value.clone(),
        }
    }
}

impl<F: PrimeField, const BIT: u32> R1CSVar<F> for GeneralUint<F, BIT> {
    type Value = u128;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.value.get()
    }
}

impl<F: PrimeField, const BIT: u32> GeneralUint<F, BIT> {
    pub fn new_witness(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<u128, SynthesisError>,
        bits: u32,
    ) -> Result<Self, SynthesisError> {
        debug_assert!(F::Params::MODULUS_BITS > BIT * 2);

        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;

        assert!(bits <= BIT);
        assert!(v < 1u128 << bits);

        let (_, lc) = (0..bits)
            .into_iter()
            .try_fold((F::one(), lc!()), |(coeff, lc), i| {
                let bit = AllocatedBool::new_witness(cs.clone(), || Ok((v >> i) & 1 == 1))?;
                Ok((coeff.double(), lc + (coeff, bit.variable())))
            })?;

        Ok(Self {
            variable: cs.new_lc(lc)?,
            cs,
            value: Some(v),
        })
    }

    pub fn from_fp_var(fp_var: FpVar<F>) -> Result<Vec<Self>, SynthesisError> {
        debug_assert!(F::Params::CAPACITY <= BIT * 2);
        assert!(F::Params::MODULUS_BITS >= BIT * 2);

        if let FpVar::Var(fp_var) = fp_var {
            let ref cs = fp_var.cs;
            let base = BigUint::from(1u128 << BIT);
            let base_field = F::from(1u128 << BIT);
            let fp_field = fp_var.value()?;
            let mut rest: BigUint = fp_field.into_repr().into();
            let mut res = Vec::new();

            let (mut lc, coeff) = (0..F::Params::MODULUS_BITS / BIT)
                .into_iter()
                .try_fold((lc!(), F::one()), |(lc, coeff), _| {
                    let (r, lo) = rest.div_rem(&base);
                    rest = r;

                    let lo_var = Self::new_witness(cs.clone(), || lo.to_u128().get(), BIT)?;
                    let var = lo_var.variable;
                    res.push(lo_var);

                    Ok((lc + (coeff, var), coeff * base_field))
                })?;

            if F::Params::MODULUS_BITS % BIT != 0 {
                let bits = F::Params::MODULUS_BITS % BIT;
                let lo_var = Self::new_witness(cs.clone(), || rest.to_u128().get(), bits)?;
                lc += (coeff, lo_var.variable);
                res.push(lo_var);
            }

            fp_var.cs.enforce_constraint(
                lc!() + fp_var.variable,
                lc!() + Variable::One,
                lc,
            )?;

            Ok(res)
        } else {
            unreachable!("fp var should not be constant");
        }
    }

    pub fn mul_constant(&self, other: u128) -> Result<(Self, Self), SynthesisError> {
        assert!(other < 1u128 << BIT);
        assert!(other > 1);

        let bits = 128 - (other - 1).leading_zeros();
        let base = BigUint::from(1u128 << BIT);
        let product = BigUint::from(self.value()?) * BigUint::from(other);
        let (hi, lo) = product.div_rem(&base);

        let hi = Self::new_witness(self.cs.clone(), || hi.to_u128().get(), bits)?;
        let lo = Self::new_witness(self.cs.clone(), || lo.to_u128().get(), BIT)?;

        self.cs.enforce_constraint(
            lc!() + (F::from(other), self.variable),
            lc!() + Variable::One,
            lc!() + (F::from(base), hi.variable) + lo.variable,
        )?;

        Ok((hi, lo))
    }

    pub fn add_with_carry_and_carry_out(
        &self,
        other: &Self,
        carry: Boolean<F>,
    ) -> Result<(Boolean<F>, Self), SynthesisError> {
        let base = BigUint::from(1u128 << BIT);
        let sum = BigUint::from(self.value()?) + BigUint::from(other.value()?) + BigUint::from(carry.value()? as u8);
        let (new_carry, sum) = if &sum >= &base {
            (true, &sum - &base)
        } else {
            (false, sum)
        };
    
        let new_carry = AllocatedBool::new_witness(self.cs.clone(), || Ok(new_carry))?;
        let sum = Self::new_witness(self.cs.clone(), || sum.to_u128().get(), BIT)?;

        self.cs.enforce_constraint(
            carry.lc() + self.variable + other.variable,
            lc!() + Variable::One,
            lc!() + (F::from(base), new_carry.variable()) + sum.variable,
        )?;

        Ok((Boolean::from(new_carry), sum))
    }

    pub fn add_with_carry(&self, carry: &Boolean<F>) -> Result<Self, SynthesisError> {
        let v = self.value()? + carry.value()? as u128;
        let variable = self.cs.new_lc(carry.lc() + self.variable)?;

        Ok(Self {
            variable,
            cs: self.cs.clone(),
            value: Some(v),
        })
    }

    pub fn mul(&self, other: &Self) -> Result<(Self, Self), SynthesisError> {
        let base = BigUint::from(1u128 << BIT);
        let product = BigUint::from(self.value()?) * BigUint::from(other.value()?);
        let (hi, lo) = product.div_rem(&base);

        let hi = Self::new_witness(self.cs.clone(), || hi.to_u128().get(), BIT)?;
        let lo = Self::new_witness(self.cs.clone(), || lo.to_u128().get(), BIT)?;

        self.cs.enforce_constraint(
            lc!() + self.variable,
            lc!() + other.variable,
            lc!() + (F::from(base), hi.variable) + lo.variable,
        )?;

        Ok((hi, lo))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{boolean::Boolean, alloc::AllocVar};
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;

    use super::GeneralUint;

    const BITS: u32 = 126;

    type Uint126 = GeneralUint<Fr, BITS>;

    fn get_rand_uint126(rng: &mut StdRng) -> u128 {
        let mut v = u128::rand(rng);
        v &= 1u128 << 126 - 1;

        v
    }

    #[test]
    fn test_mul_constant() {
        let rng = &mut test_rng();
        let a = get_rand_uint126(rng);
        let b = get_rand_uint126(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint126::new_witness(cs.clone(), || Ok(a), BITS).unwrap();
        let _ = a_var.mul_constant(b).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_add_with_carry_and_carry_out() {
        let rng = &mut test_rng();
        let a = get_rand_uint126(rng);
        let b = get_rand_uint126(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint126::new_witness(cs.clone(), || Ok(a), BITS).unwrap();
        let b_var = Uint126::new_witness(cs.clone(), || Ok(b), BITS).unwrap();
        let carry_var = Boolean::TRUE;
        let _ = a_var.add_with_carry_and_carry_out(&b_var, carry_var).unwrap();
        
        let carry_var = Boolean::new_witness(cs.clone(), || Ok(bool::rand(rng))).unwrap();
        let _ = a_var.add_with_carry_and_carry_out(&b_var, carry_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_mul() {
        let rng = &mut test_rng();
        let a = get_rand_uint126(rng);
        let b = get_rand_uint126(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint126::new_witness(cs.clone(), || Ok(a), BITS).unwrap();
        let b_var = Uint126::new_witness(cs.clone(), || Ok(b), BITS).unwrap();
        let _ = a_var.mul(&b_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}