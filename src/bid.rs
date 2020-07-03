//! Bid data structure

use crate::score_gen::{compute_score, Score};
use dusk_bls12_381::Scalar;
use dusk_plonk::{constraint_system::StandardComposer, proof_system::Proof};
use failure::Error;
use jubjub::{AffinePoint, Scalar as JubJubScalar};
use poseidon252::sponge::sponge::sponge_hash;
pub(crate) mod encoding;
pub use encoding::StorageBid;

#[derive(Copy, Clone, Debug, Default)]
pub struct Bid {
    // B^R
    pub(crate) bid_tree_root: Scalar,
    // sigma^s
    pub(crate) consensus_round_seed: Scalar,
    // k^t
    pub(crate) latest_consensus_round: Scalar,
    // k^s
    pub(crate) latest_consensus_step: Scalar,
    // t_a
    pub(crate) elegibility_ts: u32,
    // t_e
    pub(crate) expiration_ts: u32,
    //
    // Public Outputs
    //
    // i (One time identity of the prover)
    pub(crate) prover_id: Scalar,
    // q (Score of the bid)
    pub(crate) score: Score,
    // b (blinder)
    pub(crate) blinder: JubJubScalar,
    // b_enc (encrypted blinder) // XXX: Scalar for now. Double check
    pub(crate) encrypted_blinder: JubJubScalar,
    // v (Bid value)
    pub(crate) value: JubJubScalar,
    // v_enc (encrypted_value)
    pub(crate) encrypted_value: JubJubScalar,
    // R = r * G
    pub(crate) randomness: AffinePoint,
    // k
    pub(crate) secret_k: Scalar,
    // m
    pub(crate) hashed_secret: Scalar,
    // pk (Public Key - Stealth Address)
    pub(crate) pk: AffinePoint,
    // c (Pedersen Commitment)
    pub(crate) c: AffinePoint,
}

impl Bid {
    pub fn init(mut self) -> Result<Self, Error> {
        // Compute and add to the Bid the `prover_id`.
        self.generate_prover_id();
        // Compute score and append it to the Bid.
        self.score = compute_score(&self)?;

        Ok(self)
    }

    /// One-time prover-id is stated to be `H(secret_k, sigma^s, k^t, k^s)`.
    ///
    /// The function performs the sponge_hash techniqe using poseidon to
    /// get the one-time prover_id and sets it in the Bid.
    pub(crate) fn generate_prover_id(&mut self) {
        self.prover_id = sponge_hash(&[
            Scalar::from_bytes(&self.secret_k.to_bytes()).unwrap(),
            self.consensus_round_seed,
            self.latest_consensus_round,
            self.latest_consensus_step,
        ]);
    }

    pub fn prove_score_generation(
        &self,
        composer: &mut StandardComposer,
    ) -> Result<Proof, Error> {
        use crate::score_gen::score::prove_correct_score_gadget;

        prove_correct_score_gadget(composer, self)?;
        // TODO: Return the proof with a pre-computed PreprocessedCircuit and
        // ProverKey
        unimplemented!()
    }
}
