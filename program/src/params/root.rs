use crate::{params::bn::Fr, bn::BigInteger256 as BigInteger};

pub const DEFAULT_ROOT_HASH: Fr = Fr::new(BigInteger::new([
    4955574794427623608,
    11593528124232313370,
    11586116842541709345,
    1237969487296314972,
]));
