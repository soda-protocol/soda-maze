use ark_ff::{PrimeField, FpParameters};
use ark_relations::{r1cs::{Namespace, SynthesisError, ConstraintSystemRef, Variable, LinearCombination}, lc};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar, Assignment, boolean::AllocatedBool, fields::fp::{FpVar, AllocatedFp}};
use num_bigint::BigUint;
use num_integer::Integer;

#[derive(Debug, Clone)]
enum UintVar<F: PrimeField> {
    Constant(F),
    Variable(Variable),
}

#[derive(Debug, Clone)]
pub struct GeneralUint<F: PrimeField> {
    variable: UintVar<F>,
    cs: ConstraintSystemRef<F>,
    value: Option<BigUint>,
    bit_size: u64,
}

impl<F: PrimeField> R1CSVar<F> for GeneralUint<F> {
    type Value = BigUint;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.value.clone().get()
    }
}

impl<F: PrimeField> GeneralUint<F> {
    pub fn zero() -> Self {
        Self {
            variable: UintVar::Constant(F::zero()),
            cs: ConstraintSystemRef::None,
            value: Some(BigUint::from(0u64)),
            bit_size: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        match self.variable {
            UintVar::Constant(constant) => constant.is_zero(),
            UintVar::Variable(variable) => variable.is_zero(),
        }
    }

    pub fn new_constant(v: BigUint) -> Self {
        let bit_size = v.bits();
        Self {
            variable: UintVar::Constant(F::from(v.clone())),
            cs: ConstraintSystemRef::None,
            value: Some(v),
            bit_size,
        }
    }
    
    pub fn new_witness(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<BigUint, SynthesisError>,
        bit_size: u64,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;

        assert!(F::Params::MODULUS_BITS as u64 > bit_size);
        assert!(v < BigUint::from(1u64) << bit_size);

        let (_, lc) = (0..bit_size)
            .into_iter()
            .try_fold((F::one(), lc!()), |(coeff, lc), i| {
                let bit = AllocatedBool::new_witness(cs.clone(), || Ok(v.bit(i)))?;
                Ok((coeff.double(), lc + (coeff, bit.variable())))
            })?;

        Ok(Self {
            variable: UintVar::Variable(cs.new_lc(lc)?),
            cs,
            value: Some(v),
            bit_size,
        })
    }

    pub fn from_fp_var<const BIT_SIZE: u64, const WITH_REST: bool>(fp_var: FpVar<F>) -> Result<Vec<Self>, SynthesisError> {
        if let FpVar::Var(fp_var) = fp_var {
            let modulus_bits = F::Params::MODULUS_BITS as u64;
            let ref cs = fp_var.cs;
            let base = BigUint::from(1u64) << BIT_SIZE;
            let base_field = F::from(base.clone());
            let fp = fp_var.value()?;
            let mut rest: BigUint = fp.into();
            let mut res = Vec::new();

            let (mut lc, coeff) = (0..modulus_bits / BIT_SIZE)
                .into_iter()
                .try_fold((lc!(), F::one()), |(lc, coeff), _| {
                    let (r, lo) = rest.div_rem(&base);
                    rest = r;

                    let lo_var = Self::new_witness(cs.clone(), || Ok(lo), BIT_SIZE)?;
                    let lc = lc + (coeff, lo_var.variable()?);
                    res.push(lo_var);

                    Ok((lc, coeff * base_field))
                })?;

            if WITH_REST && modulus_bits % BIT_SIZE != 0 {
                let bit_size = modulus_bits % BIT_SIZE;
                let lo_var = Self::new_witness(cs.clone(), || Ok(rest), bit_size)?;
                lc += (coeff, lo_var.variable()?);
                res.push(lo_var);
            }

            fp_var.cs.enforce_constraint(
                LinearCombination::from(fp_var.variable),
                LinearCombination::from(Variable::One),
                lc,
            )?;

            Ok(res)
        } else {
            unreachable!("fp var should not be constant");
        }
    }

    pub fn to_pub_fp_var<const BIT_SIZE: u64>(array: &[Self]) -> Result<FpVar<F>, SynthesisError> {
        let mut cs = ConstraintSystemRef::None;
        let (_, lc, val) = array.iter().try_fold(
            (BigUint::from(1u64), lc!(), BigUint::from(0u64)),
            |(base, lc, val), elem| {
                assert_eq!(elem.bit_size, BIT_SIZE);

                if cs.is_none() && !elem.cs.is_none() {
                    cs = elem.cs.clone();
                }
                let base = base * (BigUint::from(1u64) << BIT_SIZE);
                let val = val + &base * elem.value()?;
                let lc = lc + (F::from(base.clone()), elem.variable()?);
                
                Ok((base, lc, val))
            })?;
        assert!(val < F::Params::MODULUS.into());
       
        if cs.is_none() {
            Err(SynthesisError::MissingCS)
        } else {
            let fp_var = AllocatedFp::new_input(cs.clone(), || Ok(F::from(val)))?;
            cs.enforce_constraint(
                LinearCombination::from(fp_var.variable),
                LinearCombination::from(Variable::One),
                LinearCombination::from(cs.new_lc(lc)?),
            )?;

            Ok(fp_var.into())
        }
    }

    pub fn variable(&self) -> Result<Variable, SynthesisError> {
        match self.variable {
            UintVar::Constant(constant) => self.cs.new_lc(LinearCombination::from((constant, Variable::One))),
            UintVar::Variable(variable) => Ok(variable),
        }
    }

    pub fn lc(&self) -> LinearCombination<F> {
        match self.variable {
            UintVar::Constant(constant) => LinearCombination::from((constant, Variable::One)),
            UintVar::Variable(variable) => LinearCombination::from(variable),
        }
    }

    pub fn mul(&self, other: &Self) -> Result<Self, SynthesisError> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }

        let product = self.value()? * other.value()?;
        let modulus: BigUint = F::Params::MODULUS.into();
        assert!(product < modulus);

        let bit_size = self.bit_size + other.bit_size;
        let value = Some(product.clone());
        Ok(match self.variable {
            UintVar::Constant(constant) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        Self {
                            variable: UintVar::Constant(constant * other_constant),
                            cs: ConstraintSystemRef::None,
                            value,
                            bit_size,
                        }
                    }
                    UintVar::Variable(variable) => {
                        let variable = other.cs.new_lc(LinearCombination::from((constant, variable)))?;
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: other.cs.clone(),
                            value,
                            bit_size,
                        }
                    }
                }
            }
            UintVar::Variable(variable) => {
                match other.variable {
                    UintVar::Constant(constant) => {
                        let variable = self.cs.new_lc(LinearCombination::from((constant, variable)))?;
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: self.cs.clone(),
                            value,
                            bit_size,
                        }
                    }
                    UintVar::Variable(other_variable) => {
                        let new_variable = self.cs.new_witness_variable(|| Ok(product.into()))?;
                        self.cs.enforce_constraint(
                            LinearCombination::from(variable),
                            LinearCombination::from(other_variable),
                            LinearCombination::from(new_variable),
                        )?;
                        Self {
                            variable: UintVar::Variable(new_variable),
                            cs: self.cs.clone(),
                            value,
                            bit_size,
                        }
                    }
                }
            }
        })
    }

    pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
        if self.is_zero() {
            return Ok(other.clone());
        } else if other.is_zero() {
            return Ok(self.clone());
        }

        let a = self.value()?;
        let b = other.value()?;
        let sum = &a + &b;
        let modulus: BigUint = F::Params::MODULUS.into();
        assert!(sum < modulus);

        let value = Some(sum.clone());        
        Ok(match self.variable {
            UintVar::Constant(constant) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        Self {
                            variable: UintVar::Constant(constant + other_constant),
                            cs: ConstraintSystemRef::None,
                            value,
                            bit_size: sum.bits(),
                        }
                    }
                    UintVar::Variable(variable) => {
                        let variable = other.cs.new_lc(LinearCombination::from(variable) + (constant, Variable::One))?;
                        let max_b = (BigUint::from(1u64) << other.bit_size) - BigUint::from(1u64);
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: other.cs.clone(),
                            value,
                            bit_size: (a + max_b).bits(),
                        }
                    }
                }
            }
            UintVar::Variable(variable) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        let variable = self.cs.new_lc(LinearCombination::from(variable) + (other_constant, Variable::One))?;
                        let max_a = (BigUint::from(1u64) << self.bit_size) - BigUint::from(1u64);
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: self.cs.clone(),
                            value,
                            bit_size: (max_a + b).bits(),
                        }
                    }
                    UintVar::Variable(other_variable) => {
                        let variable = self.cs.new_lc(LinearCombination::from(variable) + other_variable)?;
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: self.cs.clone(),
                            value,
                            bit_size: a.bits().max(b.bits()) + 1,
                        }
                    }
                }
            }
        })
    }

    pub fn split(&self, bits: u64) -> Result<(Self, Self), SynthesisError> {
        assert!(bits > 0);

        if bits >= self.bit_size {
            Ok((Self::zero(), self.clone()))
        } else {
            let base = BigUint::from(1u64) << bits;
            let (hi, lo) = self.value()?.div_rem(&base);
    
            Ok(match self.variable {
                UintVar::Constant(_) => (Self::new_constant(hi), Self::new_constant(lo)),
                UintVar::Variable(variable) => {
                    let lo = Self::new_witness(self.cs.clone(), || Ok(lo), bits)?;
                    let hi = Self::new_witness(self.cs.clone(), || Ok(hi), self.bit_size - bits)?;
    
                    self.cs.enforce_constraint(
                        LinearCombination::from(variable),
                        LinearCombination::from(Variable::One),
                        lo.lc() + (F::from(base), hi.variable()?),
                    )?;
    
                    (hi, lo)
                }
            })
        }
    }

    pub fn force_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        match self.variable {
            UintVar::Constant(constant) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        assert_eq!(constant, other_constant);
                        Ok(())
                    }
                    UintVar::Variable(variable) => {
                        other.cs.enforce_constraint(
                            LinearCombination::from(variable),
                            LinearCombination::from(Variable::One),
                            LinearCombination::from((constant, Variable::One)),
                        )
                    }
                }
            }
            UintVar::Variable(variable) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        self.cs.enforce_constraint(
                            LinearCombination::from(variable),
                            LinearCombination::from(Variable::One),
                            LinearCombination::from((other_constant, Variable::One)),
                        )
                    }
                    UintVar::Variable(other_variable) => {
                        self.cs.enforce_constraint(
                            LinearCombination::from(variable),
                            LinearCombination::from(Variable::One),
                            LinearCombination::from(other_variable),
                        )
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{fields::fp::FpVar, alloc::AllocVar};
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use ark_relations::r1cs::ConstraintSystem;
    use num_bigint::BigUint;

    use super::GeneralUint;

    const BITS: u64 = 124;

    type Uint124 = GeneralUint<Fr>;

    fn get_rand_uint124(rng: &mut StdRng) -> BigUint {
        let mut v = u128::rand(rng);
        v &= (1u128 << 124) - 1;

        BigUint::from(v)
    }

    #[test]
    fn test_from_fp_var() {
        let rng = &mut test_rng();
        let fr = Fr::rand(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let fp_var = FpVar::new_witness(cs.clone(), || Ok(fr)).unwrap();

        let res = GeneralUint::from_fp_var::<BITS, true>(fp_var).unwrap();
        assert_eq!(res.len(), 3);
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_mul() {
        let rng = &mut test_rng();
        let a = get_rand_uint124(rng);
        let b = get_rand_uint124(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_constant(a.clone());
        let b_var = Uint124::new_constant(b.clone());
        let _ = a_var.mul(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        let b_var = Uint124::new_constant(b.clone());
        let _ = a_var.mul(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_witness(cs.clone(), || Ok(a), BITS).unwrap();
        let b_var = Uint124::new_witness(cs.clone(), || Ok(b), BITS).unwrap();
        let _ = a_var.mul(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_add() {
        let rng = &mut test_rng();
        let a = get_rand_uint124(rng);
        let b = get_rand_uint124(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_constant(a.clone());
        let b_var = Uint124::new_constant(b.clone());
        let _ = a_var.add(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let a_var = Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        let b_var = Uint124::new_constant(b.clone());
        let _ = a_var.add(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        let b_var = Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap();
        let _ = a_var.add(&b_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_split() {
        let rng = &mut test_rng();
        let a = get_rand_uint124(rng);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_constant(a.clone());
        let _ = a_var.split(62).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        let _ = a_var.split(62).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());
    }
}