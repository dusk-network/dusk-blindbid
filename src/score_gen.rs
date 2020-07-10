pub(crate) mod errors;
pub mod score;
pub(crate) use score::{
    compute_score, prove_correct_score_gadget, single_complex_range_proof,
};

pub use score::Score;
