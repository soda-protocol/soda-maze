mod deposit;

pub use deposit::*;

use crate::params::{G1Projective254, G1Affine254, EllCoeffFq2, Fqk254};

pub struct PreparedVerifyingKey<'a> {
    /// 
    pub g_ic_init: &'a G1Projective254,
    /// The unprepared verification key.
    pub gamma_abc_g1: &'a [G1Affine254],
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: &'a Fqk254,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: &'a [EllCoeffFq2],
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: &'a [EllCoeffFq2],
}