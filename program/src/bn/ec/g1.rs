use super::{BnParameters, GroupAffine, GroupProjective};

pub type G1Affine<P> = GroupAffine<<P as BnParameters>::G1Parameters>;
pub type G1Projective<P> = GroupProjective<<P as BnParameters>::G1Parameters>;
