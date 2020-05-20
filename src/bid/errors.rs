//! Errors related to the Bid

use failure::Error;
use failure::Fail;

/// Definition of the erros that Bid operations might have.
#[derive(Fail, Debug)]
pub enum BidError {
    /// Error for the cases when we encode a `Bid` that does not have
    /// computed the `prover_id` or the `score`.
    #[fail(display = "bid doesn't have computed all of it's fields")]
    MissingBidFields,
    /// Error triggers when we try to collapse a byte-accumulator that
    /// is not correctly padded.
    #[fail(display = "byte_accumulator length is not correct")]
    WrongPadding,
}
