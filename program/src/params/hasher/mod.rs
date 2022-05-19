pub mod bn254_x3_3;
pub mod bn254_x5_4;

use super::bn::Fr;

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct PoseidonParameters<'a> {
	/// The round key constants
	pub round_keys: &'a [Fr],
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: &'a [&'a [Fr]],
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: i8,
}

macro_rules! impl_get_params {
    ($func:ident, $name:ident) => {
        pub const fn $func() -> PoseidonParameters<'static> {
            PoseidonParameters {
                round_keys: $name::ROUND_KEYS,
                mds_matrix: $name::MDS_MATRIX,
                full_rounds: $name::FULL_ROUNDS,
                partial_rounds: $name::PARTIAL_ROUNDS,
                width: $name::WIDTH,
                sbox: $name::SBOX,
            }
        }
    };
}

impl_get_params!(get_params_bn254_x3_3, bn254_x3_3);
impl_get_params!(get_params_bn254_x5_4, bn254_x5_4);
