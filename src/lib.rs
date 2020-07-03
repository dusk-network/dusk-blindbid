//! BlindBid impl

pub mod bid;
pub mod proof;
pub mod score_gen;

/// The minimum amount user is permitted to bid
pub const V_MIN: u64 = 50_000;
/// The maximum amount user is permitted to bid
pub const V_MAX: u64 = 250_000;

// TODO:
// Temporary at crate level, since this should be moved to bls12_381 or jubjub
// lib
pub(crate) fn jubjub_scalar_to_bls12_381(
    jubjub_scalar: jubjub::Scalar,
) -> dusk_bls12_381::Scalar {
    let scalar = dusk_bls12_381::Scalar::from_bytes(&jubjub_scalar.to_bytes());

    if scalar.is_none().into() {
        panic!("Failed to convert a Scalar from JubJub to BLS Scalar field.");
    }

    scalar.unwrap()
}
