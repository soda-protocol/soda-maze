mod pvk;

use crate::params::bn::{G1Projective254, G1Affine254, EllCoeffFq2, Fqk254};

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

pub const fn get_prepared_verifying_key() -> PreparedVerifyingKey<'static> {
    PreparedVerifyingKey {
        g_ic_init: pvk::G_IC_INIT,
        gamma_abc_g1: pvk::GAMMA_ABC_G1,
        alpha_g1_beta_g2: pvk::ALPHA_G1_BETA_G2,
        gamma_g2_neg_pc: pvk::GAMMA_G2_NEG_PC,
        delta_g2_neg_pc: pvk::DELTA_G2_NEG_PC,
    }
}