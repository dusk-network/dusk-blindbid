//! Bid data structure

pub(crate) use crate::bid::StorageBid;
use crate::score_gen::{compute_score, Score};
use dusk_plonk::jubjub::{
    AffinePoint, ExtendedPoint, GENERATOR, GENERATOR_NUMS,
};
use dusk_plonk::prelude::*;
use failure::Error;
use poseidon252::{cipher::PoseidonCipher, sponge::sponge::sponge_hash};

#[derive(Copy, Clone, Debug, Default)]
pub struct Bid {
    // B^R
    pub(crate) bid_tree_root: BlsScalar,
    // sigma^s
    pub(crate) consensus_round_seed: BlsScalar,
    // k^t
    pub(crate) latest_consensus_round: BlsScalar,
    // k^s
    pub(crate) latest_consensus_step: BlsScalar,
    // t_a
    pub(crate) elegibility_ts: u32,
    // t_e
    pub(crate) expiration_ts: u32,
    // i (One time identity of the prover)
    pub(crate) prover_id: BlsScalar,
    // q (Score of the bid)
    pub(crate) score: Score,
    // b (blinder)
    pub(crate) blinder: JubJubScalar,
    // b_enc (encrypted blinder)
    pub(crate) encrypted_blinder: PoseidonCipher,
    // v (Bid value)
    pub(crate) value: JubJubScalar,
    // v_enc (encrypted_value)
    pub(crate) encrypted_value: PoseidonCipher,
    // R = r * G
    pub(crate) randomness: AffinePoint,
    // k
    pub(crate) secret_k: BlsScalar,
    // m
    pub(crate) hashed_secret: BlsScalar,
    // pk (Public Key - Stealth Address)
    pub(crate) pk: AffinePoint,
    // c (Pedersen Commitment)
    pub(crate) c: AffinePoint,
    // n (Nonce)
    pub(crate) n: BlsScalar,
}

impl Bid {
    pub fn init(mut self) -> Result<Self, Error> {
        // Compute and add the `hashed_secret` to the Bid.
        self.hashed_secret = sponge_hash(&[self.secret_k]);
        // Compute the encrypted value & blinder and add them to
        // the `Bid` struct.
        self.encrypted_value = PoseidonCipher::encrypt(
            &[self.value.into()],
            &self.randomness,
            &self.n,
        );
        self.encrypted_blinder = PoseidonCipher::encrypt(
            &[self.blinder.into()],
            &self.randomness,
            &self.n,
        );
        // Compute and add to the Bid the `prover_id`.
        self.generate_prover_id();
        // Compute score and append it to the Bid.
        self.score = compute_score(&self)?;
        // Compute the Pedersen Commitment with the value and the blinder
        self.c = {
            let p1 = ExtendedPoint::from(GENERATOR) * self.value;
            let p2 = ExtendedPoint::from(GENERATOR_NUMS) * self.blinder;
            (p1 + p2).into()
        };
        Ok(self)
    }

    /// One-time prover-id is stated to be `H(secret_k, sigma^s, k^t, k^s)`.
    ///
    /// The function performs the sponge_hash techniqe using poseidon to
    /// get the one-time prover_id and sets it in the Bid.
    pub(crate) fn generate_prover_id(&mut self) {
        self.prover_id = sponge_hash(&[
            BlsScalar::from_bytes(&self.secret_k.to_bytes()).unwrap(),
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

        unimplemented!()
    }
}
