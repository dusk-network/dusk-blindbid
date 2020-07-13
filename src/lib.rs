//! BlindBid impl

pub mod bid;
pub mod proof;
pub mod score_gen;

/// The minimum amount user is permitted to bid
pub const V_MIN: u64 = 50_000;
/// The maximum amount user is permitted to bid
pub const V_MAX: u64 = 250_000;
