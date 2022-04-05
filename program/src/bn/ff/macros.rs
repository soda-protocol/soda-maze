#[macro_export]
macro_rules! impl_Fp {
    ($Fp:ident, $FpParameters:ident, $BigInteger:ident, $BigIntegerType:ty, $limbs:expr, $field_size:expr) => {
        pub trait $FpParameters: FpParameters<BigInteger = $BigIntegerType> {}

        /// Represents an element of the prime field F_p, where `p == P::MODULUS`.
        /// This type can represent elements in any field of size at most
        /// bits.
        #[derive(BorshSerialize, BorshDeserialize)]
        pub struct $Fp<P>(
            pub $BigIntegerType,
            #[doc(hidden)]
            pub std::marker::PhantomData<P>,
        );

        impl<P> $Fp<P> {
            #[inline]
            pub const fn new(element: $BigIntegerType) -> Self {
                Self(element, std::marker::PhantomData)
            }

            fn mul_without_reduce(mut self, other: &Self, modulus: $BigIntegerType, inv: u64) -> Self {
                let mut r = [0u64; $limbs * 2];

                for i in 0..$limbs {
                    let mut carry = 0;
                    for j in 0..$limbs {
                        r[j + i] = mac_with_carry!(r[j + i], (self.0).0[i], (other.0).0[j], &mut carry);
                    }
                    r[$limbs + i] = carry;
                }
                // Montgomery reduction
                let mut _carry2 = 0;
                for i in 0..$limbs {
                    let k = r[i].wrapping_mul(inv);
                    let mut carry = 0;
                    mac_with_carry!(r[i], k, modulus.0[0], &mut carry);
                    for j in 1..$limbs {
                        r[j + i] = mac_with_carry!(r[j + i], k, modulus.0[j], &mut carry);
                    }
                    r[$limbs + i] = adc!(r[$limbs + i], _carry2, &mut carry);
                    _carry2 = carry;
                }

                for i in 0..$limbs {
                    (self.0).0[i] = r[$limbs + i];
                }
                self
            }
        }

        impl<P> AsRef<[u64]> for $Fp<P> {
            #[inline]
            fn as_ref(&self) -> &[u64] {
                self.0.as_ref()
            }
        }

        impl<P: $FpParameters> $Fp<P> {
            #[inline(always)]
            pub(crate) fn is_valid(&self) -> bool {
                self.0 < P::MODULUS
            }

            #[inline]
            fn reduce(&mut self) {
                if !self.is_valid() {
                    self.0.sub_noborrow(&P::MODULUS);
                }
            }
        }

        impl<P> Clone for $Fp<P> {
            #[inline]
            fn clone(&self) -> Self {
                Self::new(self.0.clone())
            }
        }

        impl<P> Copy for $Fp<P> {}

        impl<P> PartialEq for $Fp<P> {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.0.eq(&other.0)
            }
        }

        impl<P> Eq for $Fp<P> {}

        impl<P: $FpParameters> Zero for $Fp<P> {
            #[inline]
            fn zero() -> Self {
                $Fp::<P>($BigInteger::from(0), std::marker::PhantomData)
            }

            #[inline]
            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl<P: $FpParameters> One for $Fp<P> {
            #[inline]
            fn one() -> Self {
                $Fp::<P>(P::R, std::marker::PhantomData)
            }

            #[inline]
            fn is_one(&self) -> bool {
                self.0 == P::R
            }
        }

        impl<P: $FpParameters> Field for $Fp<P> {
            const CHARACTERISTIC: &'static [u64] = &P::MODULUS.0;

            #[inline]
            fn double(&self) -> Self {
                let mut temp = *self;
                temp.double_in_place();
                temp
            }

            #[inline]
            fn double_in_place(&mut self) -> &mut Self {
                // This cannot exceed the backing capacity.
                self.0.mul2();
                // However, it may need to be reduced.
                self.reduce();
                self
            }

            #[inline]
            fn square(&self) -> Self {
                let mut temp = self.clone();
                temp.square_in_place();
                temp
            }

            impl_field_square_in_place!($limbs);

            #[inline]
            fn inverse(&self) -> Option<Self> {
                if self.is_zero() {
                    None
                } else {
                    // Guajardo Kumar Paar Pelzl
                    // Efficient Software-Implementation of Finite Fields with Applications to
                    // Cryptography
                    // Algorithm 16 (BEA for Inversion in Fp)

                    let one = $BigInteger::from(1);

                    let mut u = self.0;
                    let mut v = P::MODULUS;
                    let mut b = $Fp::<P>(P::R2, std::marker::PhantomData); // Avoids unnecessary reduction step.
                    let mut c = Self::zero();

                    while u != one && v != one {
                        while u.is_even() {
                            u.div2();

                            if b.0.is_even() {
                                b.0.div2();
                            } else {
                                b.0.add_nocarry(&P::MODULUS);
                                b.0.div2();
                            }
                        }

                        while v.is_even() {
                            v.div2();

                            if c.0.is_even() {
                                c.0.div2();
                            } else {
                                c.0.add_nocarry(&P::MODULUS);
                                c.0.div2();
                            }
                        }

                        if v < u {
                            u.sub_noborrow(&v);
                            b.sub_assign(&c);
                        } else {
                            v.sub_noborrow(&u);
                            c.sub_assign(&b);
                        }
                    }

                    if u == one {
                        Some(b)
                    } else {
                        Some(c)
                    }
                }
            }

            /// The Frobenius map has no effect in a prime field.
            #[inline]
            fn frobenius_map(&mut self, _: usize) {}
        }

        impl<P: $FpParameters> Neg for $Fp<P> {
            type Output = Self;
            #[inline]
            #[must_use]
            fn neg(self) -> Self {
                if !self.is_zero() {
                    let mut tmp = P::MODULUS;
                    tmp.sub_noborrow(&self.0);
                    $Fp::<P>(tmp, std::marker::PhantomData)
                } else {
                    self
                }
            }
        }

        impl<'a, P: $FpParameters> Add<&'a $Fp<P>> for $Fp<P> {
            type Output = Self;

            #[inline]
            fn add(mut self, other: &Self) -> Self {
                self.add_assign(other);
                self
            }
        }

        impl<'a, P: $FpParameters> Sub<&'a $Fp<P>> for $Fp<P> {
            type Output = Self;

            #[inline]
            fn sub(mut self, other: &Self) -> Self {
                self.sub_assign(other);
                self
            }
        }

        impl<'a, P: $FpParameters> Mul<&'a $Fp<P>> for $Fp<P> {
            type Output = Self;

            #[inline]
            fn mul(mut self, other: &Self) -> Self {
                self.mul_assign(other);
                self
            }
        }

        impl_additive_ops_from_ref!($Fp, $FpParameters);
        impl_multiplicative_ops_from_ref!($Fp, $FpParameters);

        impl<'a, P: $FpParameters> AddAssign<&'a Self> for $Fp<P> {
            #[inline]
            fn add_assign(&mut self, other: &Self) {
                // This cannot exceed the backing capacity.
                self.0.add_nocarry(&other.0);
                // However, it may need to be reduced
                self.reduce();
            }
        }

        impl<'a, P: $FpParameters> SubAssign<&'a Self> for $Fp<P> {
            #[inline]
            fn sub_assign(&mut self, other: &Self) {
                // If `other` is larger than `self`, add the modulus to self first.
                if other.0 > self.0 {
                    self.0.add_nocarry(&P::MODULUS);
                }
                self.0.sub_noborrow(&other.0);
            }
        }

        impl<'a, P: $FpParameters> MulAssign<&'a Self> for $Fp<P> {
            #[inline]
            fn mul_assign(&mut self, other: &Self) {
                // Checking the modulus at compile time
                let first_bit_set = P::MODULUS.0[$limbs - 1] >> 63 != 0;
                // $limbs can be 1, hence we can run into a case with an unused mut.
                #[allow(unused_mut)]
                let mut all_bits_set = P::MODULUS.0[$limbs - 1] == !0 - (1 << 63);
                for i in 1..$limbs {
                    all_bits_set &= P::MODULUS.0[$limbs - i - 1] == !0u64;
                }
                let _no_carry: bool = !(first_bit_set || all_bits_set);

                // No-carry optimisation applied to CIOS
                if _no_carry {
                    let mut r = [0u64; $limbs];
                    let mut carry1 = 0u64;
                    let mut carry2 = 0u64;

                    for i in 0..$limbs {
                        r[0] = mac(r[0], (self.0).0[0], (other.0).0[i], &mut carry1);
                        let k = r[0].wrapping_mul(P::INV);
                        mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
                        for j in 1..$limbs {
                            r[j] = mac_with_carry!(r[j], (self.0).0[j], (other.0).0[i], &mut carry1);
                            r[j - 1] = mac_with_carry!(r[j], k, P::MODULUS.0[j], &mut carry2);
                        }
                        r[$limbs - 1] = carry1 + carry2;
                    }
                    (self.0).0 = r;
                    self.reduce();
                // Alternative implementation
                } else {
                    *self = self.mul_without_reduce(other, P::MODULUS, P::INV);
                    self.reduce();
                }
            }
        }
    }
}
