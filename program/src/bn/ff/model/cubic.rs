use std::marker::PhantomData;
use std::ops::{Neg, Add, Sub, Mul, AddAssign, SubAssign, MulAssign};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};

use crate::bn::ff::Field;
use crate::{impl_additive_ops_from_ref, impl_multiplicative_ops_from_ref};

pub trait CubicExtParameters: 'static + Sized {
    /// The base field that this field is a cubic extension of.
    type BaseField: Field;
    /// The type of the coefficients for an efficient implemntation of the
    /// Frobenius endomorphism.
    type FrobCoeff: Field;

    /// The degree of the extension over the base prime field.
    const DEGREE_OVER_BASE_PRIME_FIELD: usize;

    /// The cubic non-residue used to construct the extension.
    const NONRESIDUE: Self::BaseField;

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_C1: &'static [Self::FrobCoeff];
    const FROBENIUS_COEFF_C2: &'static [Self::FrobCoeff];

    /// A specializable method for multiplying an element of the base field by
    /// the quadratic non-residue. This is used in multiplication and squaring.
    #[inline(always)]
    fn mul_base_field_by_nonresidue(fe: &Self::BaseField) -> Self::BaseField {
        Self::NONRESIDUE * fe
    }

    /// A specializable method for multiplying an element of the base field by
    /// the appropriate Frobenius coefficient.
    fn mul_base_field_by_frob_coeff(
        c1: &mut Self::BaseField,
        c2: &mut Self::BaseField,
        power: usize,
    );
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct CubicExtField<P: CubicExtParameters> {
    pub c0: P::BaseField,
    pub c1: P::BaseField,
    pub c2: P::BaseField,
    pub _p: PhantomData<P>,
}

impl<P: CubicExtParameters> Clone for CubicExtField<P> {
    #[inline(always)]
    fn clone(&self) -> Self {
        CubicExtField {
            c0: self.c0.clone(),
            c1: self.c1.clone(),
            c2: self.c2.clone(),
            _p: Default::default(),
        }
    }
}

impl<P: CubicExtParameters> Copy for CubicExtField<P> {}

impl<P: CubicExtParameters> CubicExtField<P> {
    pub fn new(c0: P::BaseField, c1: P::BaseField, c2: P::BaseField) -> Self {
        CubicExtField {
            c0,
            c1,
            c2,
            _p: PhantomData,
        }
    }
}

impl<P: CubicExtParameters> Zero for CubicExtField<P> {
    fn zero() -> Self {
        CubicExtField {
            c0: P::BaseField::zero(),
            c1: P::BaseField::zero(),
            c2: P::BaseField::zero(),
            _p: PhantomData,
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }
}

impl<P: CubicExtParameters> One for CubicExtField<P> {
    fn one() -> Self {
        CubicExtField {
            c0: P::BaseField::one(),
            c1: P::BaseField::zero(),
            c2: P::BaseField::zero(),
            _p: PhantomData,
        }
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero() && self.c2.is_zero()
    }
}

impl<P: CubicExtParameters> Field for CubicExtField<P> {
    fn characteristic() -> &'static [u64] {
        P::BaseField::characteristic()
    }

    fn extension_degree() -> u64 {
        3 * P::BaseField::extension_degree()
    }

    fn double(&self) -> Self {
        let mut result = *self;
        result.double_in_place();
        result
    }

    fn double_in_place(&mut self) -> &mut Self {
        self.c0.double_in_place();
        self.c1.double_in_place();
        self.c2.double_in_place();
        self
    }

    fn square(&self) -> Self {
        let mut result = *self;
        result.square_in_place();
        result
    }

    fn square_in_place(&mut self) -> &mut Self {
        // Devegili OhEig Scott Dahab --- Multiplication and Squaring on
        // AbstractPairing-Friendly
        // Fields.pdf; Section 4 (CH-SQR2)
        let a = self.c0;
        let b = self.c1;
        let c = self.c2;

        let s0 = a.square();
        let ab = a * &b;
        let s1 = ab.double();
        let s2 = (a - &b + &c).square();
        let bc = b * &c;
        let s3 = bc.double();
        let s4 = c.square();

        self.c0 = s0 + &P::mul_base_field_by_nonresidue(&s3);
        self.c1 = s1 + &P::mul_base_field_by_nonresidue(&s4);
        self.c2 = s1 + &s2 + &s3 - &s0 - &s4;
        self
    }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            // From "High-Speed Software Implementation of the Optimal Ate AbstractPairing
            // over
            // Barreto-Naehrig Curves"; Algorithm 17
            let t0 = self.c0.square();
            let t1 = self.c1.square();
            let t2 = self.c2.square();
            let t3 = self.c0 * &self.c1;
            let t4 = self.c0 * &self.c2;
            let t5 = self.c1 * &self.c2;
            let n5 = P::mul_base_field_by_nonresidue(&t5);

            let s0 = t0 - &n5;
            let s1 = P::mul_base_field_by_nonresidue(&t2) - &t3;
            let s2 = t1 - &t4; // typo in paper referenced above. should be "-" as per Scott, but is "*"

            let a1 = self.c2 * &s1;
            let a2 = self.c1 * &s2;
            let mut a3 = a1 + &a2;
            a3 = P::mul_base_field_by_nonresidue(&a3);
            let t6 = (self.c0 * &s0 + &a3).inverse().unwrap();

            let c0 = t6 * &s0;
            let c1 = t6 * &s1;
            let c2 = t6 * &s2;

            Some(Self::new(c0, c1, c2))
        }
    }

    fn frobenius_map(&mut self, power: usize) {
        self.c0.frobenius_map(power);
        self.c1.frobenius_map(power);
        self.c2.frobenius_map(power);

        P::mul_base_field_by_frob_coeff(&mut self.c1, &mut self.c2, power);
    }
}

impl<P: CubicExtParameters> PartialEq for CubicExtField<P> {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl<P: CubicExtParameters> Eq for CubicExtField<P> {}

impl<P: CubicExtParameters> Neg for CubicExtField<P> {
    type Output = Self;
    #[inline]
    fn neg(mut self) -> Self {
        self.c0 = -self.c0;
        self.c1 = -self.c1;
        self.c2 = -self.c2;
        self
    }
}

impl<'a, P: CubicExtParameters> Add<&'a CubicExtField<P>> for CubicExtField<P> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &Self) -> Self {
        self.add_assign(other);
        self
    }
}

impl<'a, P: CubicExtParameters> Sub<&'a CubicExtField<P>> for CubicExtField<P> {
    type Output = Self;

    #[inline]
    fn sub(mut self, other: &Self) -> Self {
        self.sub_assign(other);
        self
    }
}

impl<'a, P: CubicExtParameters> Mul<&'a CubicExtField<P>> for CubicExtField<P> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: &Self) -> Self {
        self.mul_assign(other);
        self
    }
}

impl_additive_ops_from_ref!(CubicExtField, CubicExtParameters);
impl_multiplicative_ops_from_ref!(CubicExtField, CubicExtParameters);
impl<'a, P: CubicExtParameters> AddAssign<&'a Self> for CubicExtField<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        self.c0.add_assign(&other.c0);
        self.c1.add_assign(&other.c1);
        self.c2.add_assign(&other.c2);
    }
}

impl<'a, P: CubicExtParameters> SubAssign<&'a Self> for CubicExtField<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        self.c0.sub_assign(&other.c0);
        self.c1.sub_assign(&other.c1);
        self.c2.sub_assign(&other.c2);
    }
}

impl<'a, P: CubicExtParameters> MulAssign<&'a Self> for CubicExtField<P> {
    #[inline]
    #[allow(clippy::many_single_char_names)]
    fn mul_assign(&mut self, other: &Self) {
        // Devegili OhEig Scott Dahab --- Multiplication and Squaring on
        // AbstractPairing-Friendly
        // Fields.pdf; Section 4 (Karatsuba)

        let a = other.c0;
        let b = other.c1;
        let c = other.c2;

        let d = self.c0;
        let e = self.c1;
        let f = self.c2;

        let ad = d * &a;
        let be = e * &b;
        let cf = f * &c;

        let x = (e + &f) * &(b + &c) - &be - &cf;
        let y = (d + &e) * &(a + &b) - &ad - &be;
        let z = (d + &f) * &(a + &c) - &ad + &be - &cf;

        self.c0 = ad + &P::mul_base_field_by_nonresidue(&x);
        self.c1 = y + &P::mul_base_field_by_nonresidue(&cf);
        self.c2 = z;
    }
}
