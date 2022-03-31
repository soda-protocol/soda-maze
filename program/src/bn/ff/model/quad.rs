use std::marker::PhantomData;
use std::ops::{Neg, Add, Sub, Mul, AddAssign, SubAssign, MulAssign};
use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::{Zero, One};

use crate::{impl_additive_ops_from_ref, impl_multiplicative_ops_from_ref};

use crate::bn::ff::Field;

pub trait QuadExtParameters: 'static + Sized {
    /// The base field that this field is a quadratic extension of.
    type BaseField: Field;
    /// The type of the coefficients for an efficient implemntation of the
    /// Frobenius endomorphism.
    type FrobCoeff: Field;

    /// The degree of the extension over the base prime field.
    const DEGREE_OVER_BASE_PRIME_FIELD: usize;

    /// The quadratic non-residue used to construct the extension.
    const NONRESIDUE: Self::BaseField;

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_C1: &'static [Self::FrobCoeff];

    /// A specializable method for multiplying an element of the base field by
    /// the quadratic non-residue. This is used in Karatsuba multiplication
    /// and in complex squaring.
    #[inline(always)]
    fn mul_base_field_by_nonresidue(fe: &Self::BaseField) -> Self::BaseField {
        Self::NONRESIDUE * fe
    }

    /// A specializable method for computing x + mul_base_field_by_nonresidue(y)
    /// This allows for optimizations when the non-residue is
    /// canonically negative in the field.
    #[inline(always)]
    fn add_and_mul_base_field_by_nonresidue(
        x: &Self::BaseField,
        y: &Self::BaseField,
    ) -> Self::BaseField {
        *x + Self::mul_base_field_by_nonresidue(y)
    }

    /// A specializable method for computing x + mul_base_field_by_nonresidue(y) + y
    /// This allows for optimizations when the non-residue is not -1.
    #[inline(always)]
    fn add_and_mul_base_field_by_nonresidue_plus_one(
        x: &Self::BaseField,
        y: &Self::BaseField,
    ) -> Self::BaseField {
        let mut tmp = *x;
        tmp += y;
        Self::add_and_mul_base_field_by_nonresidue(&tmp, &y)
    }

    /// A specializable method for computing x - mul_base_field_by_nonresidue(y)
    /// This allows for optimizations when the non-residue is
    /// canonically negative in the field.
    #[inline(always)]
    fn sub_and_mul_base_field_by_nonresidue(
        x: &Self::BaseField,
        y: &Self::BaseField,
    ) -> Self::BaseField {
        *x - Self::mul_base_field_by_nonresidue(y)
    }

    /// A specializable method for multiplying an element of the base field by
    /// the appropriate Frobenius coefficient.
    fn mul_base_field_by_frob_coeff(fe: &mut Self::BaseField, power: usize);

    /// A specializable method for exponentiating that is to be used
    /// *only* when `fe` is known to be in the cyclotommic subgroup.
    fn cyclotomic_exp(fe: &QuadExtField<Self>, naf: &'static [i8]) -> QuadExtField<Self> {
        let mut res = QuadExtField::one();
        let mut self_inverse = fe.clone();
        self_inverse.conjugate();

        let mut found_nonzero = false;
        for &value in naf.iter().rev() {
            if found_nonzero {
                res.square_in_place();
            }

            if value != 0 {
                found_nonzero = true;

                if value > 0 {
                    res *= fe;
                } else {
                    res *= &self_inverse;
                }
            }
        }

        res
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct QuadExtField<P: QuadExtParameters> {
    pub c0: P::BaseField,
    pub c1: P::BaseField,
    pub(crate) _p: PhantomData<P>,
}

impl<P: QuadExtParameters> Clone for QuadExtField<P> {
    #[inline(always)]
    fn clone(&self) -> Self {
        QuadExtField {
            c0: self.c0.clone(),
            c1: self.c1.clone(),
            _p: Default::default(),
        }
    }
}

impl<P: QuadExtParameters> Copy for QuadExtField<P> {}
 
impl<P: QuadExtParameters> QuadExtField<P> {
    pub fn new(c0: P::BaseField, c1: P::BaseField) -> Self {
        QuadExtField {
            c0,
            c1,
            _p: PhantomData,
        }
    }

    ////////////////////////////////////// keep ////////////////////////////////////////
    /// This is only to be used when the element is *known* to be in the cyclotomic subgroup.
    pub fn conjugate(&mut self) {
        self.c1 = -self.c1;
    }

    // ///////////////////////////////// keep ////////////////////////////
    // pub fn mul_assign_by_basefield(&mut self, element: &P::BaseField) {
    //     self.c0.mul_assign(element);
    //     self.c1.mul_assign(element);
    // }
}

impl<P: QuadExtParameters> Zero for QuadExtField<P> {
    fn zero() -> Self {
        QuadExtField::new(P::BaseField::zero(), P::BaseField::zero())
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }
}

impl<P: QuadExtParameters> One for QuadExtField<P> {
    fn one() -> Self {
        QuadExtField::new(P::BaseField::one(), P::BaseField::zero())
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero()
    }
}

impl<P: QuadExtParameters> Field for QuadExtField<P> {
    fn characteristic() -> &'static [u64] {
        P::BaseField::characteristic()
    }

    fn extension_degree() -> u64 {
        2 * P::BaseField::extension_degree()
    }

    fn double(&self) -> Self {
        let mut result = *self;
        result.double_in_place();
        result
    }

    ///////////////////////////////// keep ////////////////////////////
    fn double_in_place(&mut self) -> &mut Self {
        self.c0.double_in_place();
        self.c1.double_in_place();
        self
    }

    fn square(&self) -> Self {
        let mut result = *self;
        result.square_in_place();
        result
    }

    ///////////////////////////////// keep ////////////////////////////
    fn square_in_place(&mut self) -> &mut Self {
        // (c0, c1)^2 = (c0 + x*c1)^2
        //            = c0^2 + 2 c0 c1 x + c1^2 x^2
        //            = c0^2 + beta * c1^2 + 2 c0 * c1 * x
        //            = (c0^2 + beta * c1^2, 2 c0 * c1)
        // Where beta is P::NONRESIDUE.
        // When beta = -1, we can re-use intermediate additions to improve performance.
        if P::NONRESIDUE == -P::BaseField::one() {
            // When the non-residue is -1, we save 2 intermediate additions,
            // and use one fewer intermediate variable

            let c0_copy = self.c0;
            // v0 = c0 - c1
            let v0 = self.c0 - &self.c1;
            // result.c1 = 2 c1
            self.c1.double_in_place();
            // result.c0 = (c0 - c1) + 2c1 = c0 + c1
            self.c0 = v0 + &self.c1;
            // result.c0 *= (c0 - c1)
            // result.c0 = (c0 - c1) * (c0 + c1) = c0^2 - c1^2
            self.c0 *= &v0;
            // result.c1 *= c0
            // result.c1 = (2 * c1) * c0
            self.c1 *= &c0_copy;

            self
        } else {
            // v0 = c0 - c1
            let mut v0 = self.c0 - &self.c1;
            // v3 = c0 - beta * c1
            let v3 = P::sub_and_mul_base_field_by_nonresidue(&self.c0, &self.c1);
            // v2 = c0 * c1
            let v2 = self.c0 * &self.c1;

            // v0 = (v0 * v3)
            // v0 = (c0 - c1) * (c0 - beta*c1)
            // v0 = c0^2 - beta * c0 * c1 - c0 * c1 + beta * c1^2
            v0 *= &v3;

            // result.c1 = 2 * c0 * c1
            self.c1 = v2.double();
            // result.c0 = (v0) + ((beta + 1) * v2)
            // result.c0 = (c0^2 - beta * c0 * c1 - c0 * c1 + beta * c1^2) + ((beta + 1) c0 * c1)
            // result.c0 = (c0^2 - beta * c0 * c1 + beta * c1^2) + (beta * c0 * c1)
            // result.c0 = c0^2 + beta * c1^2
            self.c0 = P::add_and_mul_base_field_by_nonresidue_plus_one(&v0, &v2);

            self
        }
    }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            // Guide to Pairing-based Cryptography, Algorithm 5.19.
            // v1 = c1.square()
            let v1 = self.c1.square();
            // v0 = c0.square() - beta * v1
            let v0 = P::sub_and_mul_base_field_by_nonresidue(&self.c0.square(), &v1);

            // v0.inverse().map(|v1| {
            //     let c0 = self.c0 * &v1;
            //     let c1 = -(self.c1 * &v1);
            //     Self::new(c0, c1)
            // })
            let c0 = self.c0 * &v1;
            let c1 = -(self.c1 * &v1);
            Some(Self::new(c0, c1))
        }
    }

    ////////////////////////////////////// keep ////////////////////////////////////////
    fn frobenius_map(&mut self, power: usize) {
        self.c0.frobenius_map(power);
        self.c1.frobenius_map(power);
        P::mul_base_field_by_frob_coeff(&mut self.c1, power);
    }
}

impl<P: QuadExtParameters> PartialEq for QuadExtField<P> {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl<P: QuadExtParameters> Eq for QuadExtField<P> {}

// /// `QuadExtField` elements are ordered lexicographically.
// impl<P: QuadExtParameters> Ord for QuadExtField<P> {
//     #[inline(always)]
//     fn cmp(&self, other: &Self) -> Ordering {
//         match self.c1.cmp(&other.c1) {
//             Ordering::Greater => Ordering::Greater,
//             Ordering::Less => Ordering::Less,
//             Ordering::Equal => self.c0.cmp(&other.c0),
//         }
//     }
// }

impl<P: QuadExtParameters> Neg for QuadExtField<P> {
    type Output = Self;
    #[inline]
    #[must_use]
    fn neg(mut self) -> Self {
        self.c0 = -self.c0;
        self.c1 = -self.c1;
        self
    }
}

impl<'a, P: QuadExtParameters> Add<&'a QuadExtField<P>> for QuadExtField<P> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &Self) -> Self {
        self.add_assign(other);
        self
    }
}

impl<'a, P: QuadExtParameters> Sub<&'a QuadExtField<P>> for QuadExtField<P> {
    type Output = Self;

    #[inline]
    fn sub(mut self, other: &Self) -> Self {
        self.sub_assign(other);
        self
    }
}

impl<'a, P: QuadExtParameters> Mul<&'a QuadExtField<P>> for QuadExtField<P> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: &Self) -> Self {
        self.mul_assign(other);
        self
    }
}

impl<'a, P: QuadExtParameters> AddAssign<&'a Self> for QuadExtField<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        self.c0 += &other.c0;
        self.c1 += &other.c1;
    }
}

impl<'a, P: QuadExtParameters> SubAssign<&'a Self> for QuadExtField<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        self.c0 -= &other.c0;
        self.c1 -= &other.c1;
    }
}

impl_additive_ops_from_ref!(QuadExtField, QuadExtParameters);
impl_multiplicative_ops_from_ref!(QuadExtField, QuadExtParameters);

impl<'a, P: QuadExtParameters> MulAssign<&'a Self> for QuadExtField<P> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        // Karatsuba multiplication;
        // Guide to Pairing-based cryprography, Algorithm 5.16.
        let v0 = self.c0 * &other.c0;
        let v1 = self.c1 * &other.c1;

        self.c1 += &self.c0;
        self.c1 *= &(other.c0 + &other.c1);
        self.c1 -= &v0;
        self.c1 -= &v1;
        self.c0 = P::add_and_mul_base_field_by_nonresidue(&v0, &v1);
    }
}

