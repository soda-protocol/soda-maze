use ark_ff::{PrimeField, FpParameters};
use ark_std::{rand::RngCore, UniformRand};
use bitvec::{view::BitView, order::Lsb0, field::BitField};

pub type Pubkey = Array<32>;

#[derive(Clone, Copy)]
pub struct Array<const N: usize>([u8; N]);

impl<const N: usize> Default for Array<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Array<N> {
    pub fn new(value: [u8; N]) -> Self {
        Array(value)
    }

    pub fn to_field_element<F: PrimeField>(&self) -> F {
        let capacity = <F::Params>::CAPACITY as usize;

        if capacity >= 8 * N {
            F::read(&self.0[..]).unwrap()
        } else {
            let bits = self.0
                .view_bits::<Lsb0>()
                .get(0..capacity)
                .unwrap()
                .to_bitvec()
                .chunks(8)
                .map(|bits| bits.load_le())
                .collect::<Vec<u8>>();

            F::read(&bits[..]).unwrap()
        }
    }
}

impl<const N: usize> UniformRand for Array<N> {
    fn rand<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let mut value = [0u8; N];
        value.iter_mut().for_each(|v| *v = u8::rand(rng));

        Self(value)
    }
}