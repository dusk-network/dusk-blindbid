//! Bid data structure
//!

use crate::score_gen::score::compute_score;
use dusk_bls12_381::Scalar;
use jubjub::{AffinePoint, Scalar as JubJubScalar};
use poseidon252::sponge::sponge::sponge_hash;

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
    // q (Score of the bid)
    pub(crate) score: Option<Scalar>,
    //
    // Private Inputs
    //
    // v
    pub(crate) value: Scalar,
    // r
    pub(crate) randomness: Scalar,
    // k
    pub(crate) secret_k: JubJubScalar,
    // R = r * G
    pub(crate) pk: AffinePoint,
}

impl Default for Bid {
    fn default() -> Self {
        Bid {
            bid_tree_root: Scalar::zero(),
            consensus_round_seed: Scalar::zero(),
            latest_consensus_round: Scalar::zero(),
            latest_consensus_step: Scalar::zero(),
            prover_id: None,
            score: None,
            value: Scalar::zero(),
            randomness: Scalar::zero(),
            secret_k: JubJubScalar::zero(),
            pk: AffinePoint::default(),
        }
    }
}

impl Bid {
    pub fn new(
        bid_tree_root: Scalar,
        consensus_round_seed: Scalar,
        latest_consensus_round: Scalar,
        latest_consensus_step: Scalar,
        bid_value: Scalar,
        bid_randomness: Scalar,
        secret_k: JubJubScalar,
        pk: AffinePoint,
    ) -> Self {
        // Initialize the Bid with the fields we were provided.
        let mut bid = Bid {
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
            prover_id: None,
            score: None,
            value: bid_value,
            randomness: bid_randomness,
            secret_k,
            pk,
        };
        // Compute and add to the Bid the `prover_id`.
        bid.generate_prover_id();
        // Compute score and append it to the Bid.
        bid.score = Some(compute_score(&bid));

        bid
    }

    /// One-time prover-id is stated to be H(secret_k, sigma^s, k^t, k^s).
    ///
    /// The function performs the sponge_hash techniqe using poseidon to
    /// get the one-time prover_id and sets it in the Bid.
    pub(crate) fn generate_prover_id(&mut self) {
        self.prover_id = Some(sponge_hash(&[
            Scalar::from_bytes(&self.secret_k.to_bytes()).unwrap(),
            self.consensus_round_seed,
            self.latest_consensus_round,
            self.latest_consensus_step,
        ]));
    }
}
