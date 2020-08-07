//! Errors related to the Bid Generation

use failure::Fail;

/// Definition of the erros that Bid operations might have.
#[derive(Fail, Debug)]
pub enum BidGenerationError {
    /// Error for the cases when we the provided Bid value is bigger
    /// than the maximum allowed by the specs..
    #[fail(display = "maximum bid_value exceeded")]
    MaximumBidValueExceeded,
    /// Error for the cases when we the provided Bid value is lower
    /// than the minimum allowed by the specs..
    #[fail(display = "minimum bid_value not reached")]
    MinimumBidValueUnreached,
}
