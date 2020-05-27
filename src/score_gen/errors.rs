//! Errors related to the Score Generation

use failure::Fail;

/// Definition of the erros that Bid operations might have.
#[derive(Fail, Debug)]
pub enum ScoreError {
    /// Error for the cases when we the score results are too large to
    /// fit inside a `Scalar`.
    #[fail(display = "score results do not fit inside of Scalar")]
    InvalidScoreFieldsLen,
}
