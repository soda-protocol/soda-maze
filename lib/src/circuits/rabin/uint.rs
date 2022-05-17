use ark_ff::{PrimeField, FpParameters};
use ark_relations::{r1cs::{Namespace, SynthesisError, ConstraintSystemRef, Variable, LinearCombination}, lc};
use ark_r1cs_std::{alloc::AllocVar, R1CSVar, boolean::AllocatedBool};
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
    value: BigUint,
    bit_size: usize,
}

impl<F: PrimeField> R1CSVar<F> for GeneralUint<F> {
    type Value = BigUint;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(self.value.clone())
    }
}

impl<F: PrimeField> GeneralUint<F> {
    pub fn zero() -> Self {
        Self {
            variable: UintVar::Constant(F::zero()),
            cs: ConstraintSystemRef::None,
            value: BigUint::from(0u64),
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
        let bit_size = v.bits() as usize;
        Self {
            variable: UintVar::Constant(F::from(v.clone())),
            cs: ConstraintSystemRef::None,
            value: v,
            bit_size,
        }
    }
    
    pub fn new_witness(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<BigUint, SynthesisError>,
        bit_size: usize,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;

        assert!(F::Params::MODULUS_BITS as usize > bit_size);
        assert!(v < BigUint::from(1u64) << bit_size);

        let (_, lc) = (0..bit_size)
            .into_iter()
            .try_fold((F::one(), lc!()), |(coeff, lc), i| {
                let bit = AllocatedBool::new_witness(cs.clone(), || Ok(v.bit(i as u64)))?;
                Ok((coeff.double(), lc + (coeff, bit.variable())))
            })?;

        Ok(Self {
            variable: UintVar::Variable(cs.new_lc(lc)?),
            cs,
            value: v,
            bit_size,
        })
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

        let product = &self.value * &other.value;
        let modulus: BigUint = F::Params::MODULUS.into();
        assert!(product < modulus);

        let bit_size = self.bit_size + other.bit_size;
        let value = product.clone();
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

        let a = &self.value;
        let b = &other.value;
        let sum = a + b;
        let modulus: BigUint = F::Params::MODULUS.into();
        assert!(sum < modulus);

        let value = sum.clone();        
        Ok(match self.variable {
            UintVar::Constant(constant) => {
                match other.variable {
                    UintVar::Constant(other_constant) => {
                        Self {
                            variable: UintVar::Constant(constant + other_constant),
                            cs: ConstraintSystemRef::None,
                            value,
                            bit_size: sum.bits() as usize,
                        }
                    }
                    UintVar::Variable(variable) => {
                        let variable = other.cs.new_lc(LinearCombination::from(variable) + (constant, Variable::One))?;
                        let max_b = (BigUint::from(1u64) << other.bit_size) - BigUint::from(1u64);
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: other.cs.clone(),
                            value,
                            bit_size: (a + max_b).bits() as usize,
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
                            bit_size: (max_a + b).bits() as usize,
                        }
                    }
                    UintVar::Variable(other_variable) => {
                        let variable = self.cs.new_lc(LinearCombination::from(variable) + other_variable)?;
                        Self {
                            variable: UintVar::Variable(variable),
                            cs: self.cs.clone(),
                            value,
                            bit_size: self.bit_size.max(other.bit_size) as usize + 1,
                        }
                    }
                }
            }
        })
    }

    pub fn split(&self, bits: usize) -> Result<(Self, Self), SynthesisError> {
        if self.is_zero() {
            return Ok((Self::zero(), Self::zero()));
        }

        assert!(bits > 0);
        if bits >= self.bit_size {
            Ok((Self::zero(), self.clone()))
        } else {
            let base = BigUint::from(1u64) << bits;
            let (hi, lo) = self.value.div_rem(&base);
            let base_field = F::from(base);
    
            Ok(match self.variable {
                UintVar::Constant(_) => (Self::new_constant(hi), Self::new_constant(lo)),
                UintVar::Variable(variable) => {
                    let lo = Self::new_witness(self.cs.clone(), || Ok(lo), bits)?;
                    let hi = Self::new_witness(self.cs.clone(), || Ok(hi), self.bit_size - bits)?;
    
                    self.cs.enforce_constraint(
                        LinearCombination::from(variable),
                        LinearCombination::from(Variable::One),
                        lo.lc() + (base_field, hi.variable()?),
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
    use ark_std::{test_rng, UniformRand, rand::Rng};
    use ark_relations::r1cs::ConstraintSystem;
    use num_bigint::BigUint;

    use super::GeneralUint;

    const BITS: usize = 124;

    type Uint124 = GeneralUint<Fr>;

    fn get_rand_uint124<R: Rng + ?Sized>(rng: &mut R) -> BigUint {
        let mut v = u128::rand(rng);
        v &= (1u128 << 124) - 1;

        BigUint::from(v)
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
        let c_var = a_var.add(&b_var).unwrap();
        assert_eq!(c_var.bit_size, BITS + 1);
        assert!(cs.is_satisfied().unwrap());
        println!("{}", cs.num_constraints());

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = Uint124::new_witness(cs.clone(), || Ok(a.clone()), BITS).unwrap();
        let b_var = Uint124::new_witness(cs.clone(), || Ok(b.clone()), BITS).unwrap();
        let c_var = a_var.add(&b_var).unwrap();
        assert_eq!(c_var.bit_size, BITS + 1);
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