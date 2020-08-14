//! BlindBid impl

pub mod bid;
pub mod proof;
pub mod score_gen;

use dusk_plonk::jubjub::Fr as JubJubScalar;
/// The minimum amount user is permitted to bid
pub const V_MIN: &'static JubJubScalar =
    &JubJubScalar::from_raw([50_000u64, 0, 0, 0]);
/// The maximum amount user is permitted to bid
pub const V_MAX: &'static JubJubScalar =
    &JubJubScalar::from_raw([250_000u64, 0, 0, 0]);
