mod ec;
mod ff;

pub use ec::*;
pub use ff::*;

use std::marker::PhantomData;

pub struct Bn<P: BnParameters>(PhantomData<P>);

// impl<P: BnParameters> PairingEngine for Bn<P> {
    
// }