//! Score generation module
pub(crate) mod errors;
pub mod score;
pub(crate) use score::{compute_score, prove_correct_score_gadget};

pub use score::Score;
