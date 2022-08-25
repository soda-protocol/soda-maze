// use ark_ff::PrimeField;
// use std::marker::PhantomData;
// use ark_r1cs_std::{fields::{fp::FpVar, FieldVar}, eq::EqGadget, boolean::Boolean, select::{CondSelectGadget, ThreeBitCondNegLookupGadget}, ToBitsGadget};
// use ark_relations::r1cs::SynthesisError;

// use super::{JubjubParams, FixedGenerator};

// /// Perform a fixed-base scalar multiplication with
// /// `by` being in little-endian bit order.
// pub fn fixed_base_multiplication<F: PrimeField>(
//     base: FixedGenerator<F>,
//     by: &[Boolean<F>],
// ) -> Result<EdwardsPoint<F>, SynthesisError> {
//     for (chunk, window) in by.chunks(3).zip(base.iter()) {
//         let chunk_a = chunk
//             .get(0)
//             .cloned()
//             .unwrap_or_else(|| Boolean::constant(false));
//         let chunk_b = chunk
//             .get(1)
//             .cloned()
//             .unwrap_or_else(|| Boolean::constant(false));
//         let chunk_c = chunk
//             .get(2)
//             .cloned()
//             .unwrap_or_else(|| Boolean::constant(false));

//         ThreeBitCondNegLookupGadget
        
//     }
// }

// #[derive(Debug, Clone)]
// pub struct EdwardsPoint<F: PrimeField, J: JubjubParams<F>> {
//     u: FpVar<F>,
//     v: FpVar<F>,
//     _p: PhantomData<J>,
// }

// impl<F: PrimeField, J: JubjubParams<F>> EdwardsPoint<F, J> {
//     pub fn get_u(&self) -> &FpVar<F> {
//         &self.u
//     }

//     pub fn get_v(&self) -> &FpVar<F> {
//         &self.v
//     }

//     pub fn zero() -> Self {
//         Self {
//             u: FpVar::zero(),
//             v: FpVar::one(),
//             _p: Default::default(),
//         }
//     }

//     pub fn conditionally_select(&self, cond: &Boolean<F>) -> Result<Self, SynthesisError> {
//         // Compute u' = self.u if condition, and 0 otherwise
//         let u_prime = FpVar::conditionally_select(cond, &self.u, &FpVar::zero())?;
//         // Compute v' = self.v if condition, and 1 otherwise
//         let v_prime = FpVar::conditionally_select(cond, &self.v, &FpVar::one())?;

//         Ok(Self {
//             u: u_prime,
//             v: v_prime,
//             _p: Default::default(),
//         })
//     }

//     pub fn interpret(u: FpVar<F>, v: FpVar<F>) -> Result<Self, SynthesisError> {
//         // -u^2 + v^2 = 1 + du^2v^2
//         let u2 = u.square()?;
//         let v2 = v.square()?;
//         let du2v2 = &u2 * &v2 * FpVar::constant(J::EDWARDS_D);

//         let left = &v2 - &u2;
//         let right = FpVar::one() + du2v2;
//         left.enforce_equal(&right)?;

//         Ok(Self {
//             u,
//             v,
//             _p: Default::default(),
//         })
//     }

//     pub fn repr(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
//         let u = self.u.to_bits_le()?;
//         let mut v = self.v.to_bits_be()?;

//         v.push(u[0].clone());

//         Ok(v)
//     }

//     pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
//         // Compute U = (u1 + v1) * (u2 + v2)
//         let uppercase_u = (&self.u + &self.v) * (&other.u + &other.v);

//         // Compute A = v2 * u1
//         let a = &other.v * &self.u;
        
//         // Compute B = u2 * v1
//         let b = &other.u * &self.v;
        
//         // Compute C = d*A*B
//         let c = FpVar::constant(J::EDWARDS_D) * &a * &b;
        
//         // Compute u3 = (A + B) / (1 + C)
//         let u3 = (FpVar::one() + &c).inverse().map(|inv| inv * (&a + &b))?;
        
//         // Compute v3 = (U - A - B) / (1 - C)
//         let v3 = (FpVar::one() - &c).inverse().map(|inv| inv * (uppercase_u - &a - &b))?;

//         Ok(Self {
//             u: u3,
//             v: v3,
//             _p: Default::default(),
//         })
//     }

//     pub fn double(&self) -> Result<Self, SynthesisError> {
//         // Compute T = (u + v) * (u + v)
//         let t = (&self.u + &self.v).square()?;

//         // Compute A = u * v
//         let a = &self.u * &self.v;

//         // Compute C = d*A*A
//         let c = FpVar::constant(J::EDWARDS_D) * a.square()?;

//         // Compute u3 = (2.A) / (1 + C)
//         let t0 = a.double()?;
//         let u3 = (FpVar::one() + &c).inverse().map(|inv| inv * &t0)?;

//         // Compute v3 = (T - 2.A) / (1 - C)
//         let v3 = (FpVar::one() - &c).inverse().map(|inv| inv * (&t - &t0))?;

//         Ok(Self {
//             u: u3,
//             v: v3,
//             _p: Default::default(),
//         })
//     }

//     pub fn mul(&self, by: &[Boolean<F>]) -> Result<Self, SynthesisError> {
//         let (_, res) = by.iter().try_fold((Self::zero(), self.clone()), |(cur, base), bit| {
//             let thisbase = base.conditionally_select(bit)?;
//             let cur = cur.add(&thisbase)?;
//             let base = base.double()?;

//             Ok((cur, base))
//         })?;

//         Ok(res)
//     }
// }

// #[derive(Debug, Clone)]
// pub struct MontgomeryPoint<F: PrimeField, J: JubjubParams<F>> {
//     x: FpVar<F>,
//     y: FpVar<F>,
//     _p: PhantomData<J>,
// }

// impl<F: PrimeField, J: JubjubParams<F>> MontgomeryPoint<F, J> {
//     pub fn interpret_unchecked(x: FpVar<F>, y: FpVar<F>) -> Self {
//         Self { x, y, _p: Default::default() }
//     }

//     /// Converts an element in the prime order subgroup into
//     /// a point in the birationally equivalent twisted
//     /// Edwards curve.
//     pub fn into_edwards(self) -> Result<EdwardsPoint<F, J>, SynthesisError> {
//         // Compute u = (scale*x) / y
//         let t0 = FpVar::Constant(J::MONTGOMERY_SCALE) * &self.x;
//         let u = self.y.inverse().map(|inv| inv * t0)?;

//         // Compute v = (x - 1) / (x + 1)
//         let v = (&self.x + FpVar::one()).inverse().map(|inv| inv * (&self.x - FpVar::one()))?;

//         Ok(EdwardsPoint {
//             u,
//             v,
//             _p: self._p,
//         })
//     }

//     pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
//         // Compute lambda = (y2 - y1) / (x2 - x1)
//         let lambda = (&other.x - &self.x).inverse().map(|inv| inv * (&other.y - &self.y))?;

//         // Compute x' = lambda^2 - A - x1 - x2
//         let x_prime = lambda.square()? - FpVar::constant(J::MONGTOMERY_A) - &self.x - &other.x;

//         // Compute y' = -(y1 + lambda(x' - x1))
//         let y_prime = ((&x_prime - &self.x) * &lambda + &self.y).negate()?;

//         Ok(Self {
//             x: x_prime,
//             y: y_prime,
//             _p: Default::default(),
//         })
//     }
// }

