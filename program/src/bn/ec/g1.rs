use borsh::{BorshSerialize, BorshDeserialize};
use num_traits::Zero;

use super::{BnParameters, GroupAffine, GroupProjective};

pub type G1Affine<P> = GroupAffine<<P as BnParameters>::G1Parameters>;
pub type G1Projective<P> = GroupProjective<<P as BnParameters>::G1Parameters>;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct G1Prepared<P: BnParameters>(pub G1Affine<P>);

impl<P: BnParameters> From<G1Affine<P>> for G1Prepared<P> {
    fn from(other: G1Affine<P>) -> Self {
        G1Prepared(other)
    }
}

impl<P: BnParameters> G1Prepared<P> {
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

