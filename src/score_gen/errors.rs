//! Errors related to the Score Generation

use thiserror::Error;

/// Definition of the erros that Bid operations might have.
#[derive(Error, Debug)]
pub enum ScoreError {
    /// Error for the cases when we the score results are too large to
    /// fit inside a `Scalar`.
    #[error("score results do not fit inside of Scalar")]
    InvalidScoreFieldsLen,
    /// Error for computations of inverses that do not exists (non-Qr's)
    #[error("Inverse of the Scalar does not exist")]
    NonExistingInverse,
}
