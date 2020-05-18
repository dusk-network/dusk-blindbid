//! Bid data structure
//!

use dusk_bls12_381::{G1Affine, Scalar};

#[derive(Copy, Clone, Debug)]
pub struct Bid {
    // Pub Inputs
    //
    // B^R
    pub(crate) bid_tree_root: Scalar,
    // sigma^s
    pub(crate) consensus_round_seed: Scalar,
    // k^r
    pub(crate) latest_consensus_round: Scalar,
    // k^s
    pub(crate) latest_consensus_step: Scalar,
    //
    // Public Outputs
    //
    // i (One time identity of the prover)
    pub(crate) prover_id: Option<Scalar>,
    // q (Score)
    pub(crate) score: Option<Scalar>,
    //
    // Private Inputs
    //
    // v
    pub(crate) bid_value: Scalar,
    // r
    pub(crate) bid_randomness: Scalar,
    // k
    pub(crate) secret_k: Scalar,
    // R = r * G
    pub(crate) pk: G1Affine,
}
