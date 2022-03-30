/// This modular multiplication algorithm uses Montgomery
/// reduction for efficient implementation. It also additionally
/// uses the "no-carry optimization" outlined
/// [here](https://hackmd.io/@zkteam/modular_multiplication) if
/// `P::MODULUS` has (a) a non-zero MSB, and (b) at least one
/// zero bit in the rest of the modulus.

#[macro_export]
macro_rules! impl_field_square_in_place {
    ($limbs: expr) => {
        #[inline]
        #[allow(unused_braces, clippy::absurd_extreme_comparisons)]
        fn square_in_place(&mut self) -> &mut Self {
            if $limbs == 1 {
                // We default to multiplying with `self` using the `Mul` impl
                // for the 1 limb case
                *self = *self * *self;
                return self;
            }

            let mut r = [0u64; $limbs * 2];

            let mut carry = 0;
            for i in 0..$limbs {
                if i < $limbs - 1 {
                    for j in 0..$limbs {
                        if j > i {
                            r[i + j] =
                                mac_with_carry!(r[i + j], (self.0).0[i], (self.0).0[j], &mut carry);
                        }
                    }
                    r[$limbs + i] = carry;
                    carry = 0;
                }
            }
            r[$limbs * 2 - 1] = r[$limbs * 2 - 2] >> 63;
            for i in 0..$limbs {
                // This computes `r[2 * ($limbs - 1) - (i + 1)]`, but additionally
                // handles the case where the index underflows.
                // Note that we should never hit this case because it only occurs
                // when `$limbs == 1`, but we handle that separately above.
                let subtractor = (2 * ($limbs - 1usize))
                    .checked_sub(i + 1)
                    .map(|index| r[index])
                    .unwrap_or(0);
                r[2 * ($limbs - 1) - i] = (r[2 * ($limbs - 1) - i] << 1) | (subtractor >> 63);
            }
            for i in 3..$limbs {
                r[$limbs + 1 - i] = (r[$limbs + 1 - i] << 1) | (r[$limbs - i] >> 63);
            }
            r[1] <<= 1;

            for i in 0..$limbs {
                r[2 * i] = mac_with_carry!(r[2 * i], (self.0).0[i], (self.0).0[i], &mut carry);
                // need unused assignment because the last iteration of the loop produces an
                // assignment to `carry` that is unused.
                #[allow(unused_assignments)]
                {
                    r[2 * i + 1] = adc!(r[2 * i + 1], 0, &mut carry);
                }
            }
            // Montgomery reduction
            let mut _carry2 = 0;
            for i in 0..$limbs {
                let k = r[i].wrapping_mul(P::INV);
                let mut carry = 0;
                mac_with_carry!(r[i], k, P::MODULUS.0[0], &mut carry);
                for j in 1..$limbs {
                    r[j + i] = mac_with_carry!(r[j + i], k, P::MODULUS.0[j], &mut carry);
                }
                r[$limbs + i] = adc!(r[$limbs + i], _carry2, &mut carry);
                _carry2 = carry;
            }
            (self.0).0.copy_from_slice(&r[$limbs..]);
            self.reduce();
            self
        }
    };
}

// Implements AddAssign on Self by deferring to an implementation on &Self
#[macro_export]
macro_rules! impl_additive_ops_from_ref {
    ($type: ident, $params: ident) => {
        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Add<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn add(self, other: Self) -> Self {
                let mut result = self;
                result.add_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Add<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn add(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.add_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Sub<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self {
                let mut result = self;
                result.sub_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Sub<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn sub(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.sub_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::iter::Sum<Self> for $type<P> {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), core::ops::Add::add)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::iter::Sum<&'a Self> for $type<P> {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), core::ops::Add::add)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::AddAssign<Self> for $type<P> {
            fn add_assign(&mut self, other: Self) {
                self.add_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::SubAssign<Self> for $type<P> {
            fn sub_assign(&mut self, other: Self) {
                self.sub_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::AddAssign<&'a mut Self> for $type<P> {
            fn add_assign(&mut self, other: &'a mut Self) {
                self.add_assign(&*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::SubAssign<&'a mut Self> for $type<P> {
            fn sub_assign(&mut self, other: &'a mut Self) {
                self.sub_assign(&*other)
            }
        }
    };
}

// Implements AddAssign on Self by deferring to an implementation on &Self
#[macro_export]
macro_rules! impl_multiplicative_ops_from_ref {
    ($type: ident, $params: ident) => {
        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Mul<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn mul(self, other: Self) -> Self {
                let mut result = self;
                result.mul_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Mul<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn mul(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.mul_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::iter::Product<Self> for $type<P> {
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::one(), core::ops::Mul::mul)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::iter::Product<&'a Self> for $type<P> {
            fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::one(), Mul::mul)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::MulAssign<Self> for $type<P> {
            fn mul_assign(&mut self, other: Self) {
                self.mul_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::MulAssign<&'a mut Self> for $type<P> {
            fn mul_assign(&mut self, other: &'a mut Self) {
                self.mul_assign(&*other)
            }
        }
    };
}
