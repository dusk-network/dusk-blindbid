//! Bid data structure

use super::BidGenerationError;
use crate::score_gen::{compute_score, Score};
use anyhow::{Error, Result};
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::sponge::sponge_hash;
use rand_core::{CryptoRng, RngCore};

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
    // Encrypted value and blinding factor with the bidder key
    pub(crate) encrypted_data: PoseidonCipher,
    pub(crate) nonce: BlsScalar,

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
}

impl Bid {
    pub fn init<R>(
        mut self,
        rng: &mut R,
        value: &JubJubScalar,
        secret: &AffinePoint,
    ) -> Result<Self, Error>
    where
        R: RngCore + CryptoRng,
    {
        // Check if the bid_value is in the correct range, otherways, fail.
        match (
            value.reduce() > crate::V_MAX.reduce(),
            value.reduce() < crate::V_MIN.reduce(),
        ) {
            (true, false) => {
                return Err(BidGenerationError::MaximumBidValueExceeded {
                    max_val: crate::V_MAX,
                    found: *value,
                }
                .into());
            }
            (false, true) => {
                return Err(BidGenerationError::MinimumBidValueUnreached {
                    min_val: crate::V_MIN,
                    found: *value,
                }
                .into());
            }
            (false, false) => (),
            (_, _) => unreachable!(),
        }

        self.set_value(rng, value, secret);

        // Compute and add the `hashed_secret` to the Bid.
        self.hashed_secret = sponge_hash(&[self.secret_k]);
        // Compute and add to the Bid the `prover_id`.
        self.generate_prover_id();
        // Compute score and append it to the Bid.
        self.score = compute_score(&self, value)?;

        Ok(self)
    }

    pub(crate) fn set_value<R>(
        &mut self,
        rng: &mut R,
        value: &JubJubScalar,
        secret: &AffinePoint,
    ) where
        R: RngCore + CryptoRng,
    {
        let blinder = JubJubScalar::random(rng);
        self.nonce = BlsScalar::random(rng);
        self.encrypted_data = PoseidonCipher::encrypt(
            &[(*value).into(), blinder.into()],
            secret,
            &self.nonce,
        );

        self.c = AffinePoint::from(
            &(GENERATOR_EXTENDED * value)
                + &(GENERATOR_NUMS_EXTENDED * blinder),
        );
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

    /// Decrypt the underlying data provided the secret of the bidder and return a tuple containing
    /// the value and the blinder
    pub fn decrypt_data(
        &self,
        secret: &AffinePoint,
    ) -> Result<(JubJubScalar, JubJubScalar)> {
        self.encrypted_data
            .decrypt(secret, &self.nonce)
            .map(|message| {
                let value = message[0];
                let blinder = message[1];

                // TODO - Follow-up the discussion over Fq -> Fr
                let value =
                    JubJubScalar::from_raw(*value.reduce().internal_repr());
                let blinder =
                    JubJubScalar::from_raw(*blinder.reduce().internal_repr());

                (value, blinder)
            })
            .map_err(|_| Error::new(BidGenerationError::WrongSecretProvided))
    }

    pub fn prove_score_generation(
        &self,
        _composer: &mut StandardComposer,
    ) -> Result<Proof, Error> {
        //use crate::score_gen::score::prove_correct_score_gadget;

        unimplemented!()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::Rng;

    pub fn random_bid(secret: &JubJubScalar) -> Bid {
        let mut rng = rand::thread_rng();

        let secret = GENERATOR_EXTENDED * secret;
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);

        let bid = Bid {
            bid_tree_root: BlsScalar::random(&mut rng),
            consensus_round_seed: BlsScalar::random(&mut rng),
            latest_consensus_round: BlsScalar::random(&mut rng),
            latest_consensus_step: BlsScalar::random(&mut rng),
            elegibility_ts: rng.next_u32(),
            expiration_ts: rng.next_u32(),
            prover_id: BlsScalar::default(),
            score: Score::default(),

            encrypted_data: PoseidonCipher::default(),
            nonce: BlsScalar::default(),
            randomness: AffinePoint::identity(),

            secret_k: BlsScalar::random(&mut rng),
            hashed_secret: BlsScalar::default(),
            pk: AffinePoint::identity(),
            c: AffinePoint::default(),
        };

        bid.init(&mut rng, &value, &secret.into()).unwrap()
    }
}
