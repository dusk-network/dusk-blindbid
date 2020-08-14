//! Errors related to the Bid Generation

use dusk_plonk::jubjub::Fr as JubJubScalar;
use thiserror::Error;

/// Definition of the erros that Bid operations might have.
#[derive(Error, Debug)]
pub enum BidGenerationError<'a> {
    /// Error for the cases when we the provided Bid value is bigger
    /// than the maximum allowed by the specs..
    #[error(
        "maximum bid_value allowed is {max_val:?} but {found:?} was found"
    )]
    MaximumBidValueExceeded {
        /// The maximum bid_value allowed
        max_val: &'a JubJubScalar,
        /// The expected length
        found: JubJubScalar,
    },
    /// Error for the cases when we the provided Bid value is lower
    /// than the minimum allowed by the specs..
    #[error(
        "minimum bid_value required is {min_val:?} but {found:?} was found"
    )]
    MinimumBidValueUnreached {
        /// The minimum bid_value required
        min_val: &'a JubJubScalar,
        /// The expected length
        found: JubJubScalar,
    },
}
