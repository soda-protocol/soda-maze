pub mod vault;
pub mod withdraw;
pub mod node;
pub mod commitment;
pub mod deposit;
pub mod nullifier;
pub mod credential;
pub mod utxo;

use std::fmt::Debug;
use arrayref::array_refs;
use borsh::{BorshSerialize, BorshDeserialize};
use solana_program::{hash::hash, pubkey::Pubkey};

use crate::bn::{BigInteger256 as BigInteger, FpParameters};
use crate::params::bn::FrParameters;
use crate::params::{verify::ProofType, verify::PreparedVerifyingKey};
use crate::verifier::{Proof, Verifier, program::Program, prepare_inputs::PrepareInputs};

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct GroupAffine {
    pub x: BigInteger,
    pub y: BigInteger,
}

#[inline]
pub fn is_affine_valid(point: &GroupAffine) -> bool {
    is_fr_valid(&point.x) && is_fr_valid(&point.y)
}

#[inline]
pub fn pubkey_to_fr_repr(pubkey: &Pubkey) -> BigInteger {
    let h = hash(pubkey.as_ref()).to_bytes();
    let (d0, d1, d2, d3) = array_refs![&h, 8, 8, 8, 8];    
    
    BigInteger::new([
        u64::from_le_bytes(*d0),
        u64::from_le_bytes(*d1),
        u64::from_le_bytes(*d2),
        u64::from_le_bytes(*d3) & ((1u64 << 61) - 1),
    ])
}

#[inline]
pub fn is_fr_valid(fr: &BigInteger) -> bool {
    fr < &<FrParameters as FpParameters>::MODULUS
}

pub trait VanillaData: Debug + Clone + BorshSerialize + BorshDeserialize {
    const PROOF_TYPE: ProofType;
    const PVK: &'static PreparedVerifyingKey<'static> = Self::PROOF_TYPE.pvk();
    const INPUTS_LEN: usize;
    const SIZE: usize;

    fn to_public_inputs(self) -> Box<Vec<BigInteger>>;

    fn to_verifier(self, proof: Box<Proof>) -> Verifier {
        let public_inputs = self.to_public_inputs();
        let program = Program::PrepareInputs(PrepareInputs::new(
            Self::PVK,
            public_inputs,
            proof,
        ));

        Verifier::new(Self::PROOF_TYPE, program)
    }
}
