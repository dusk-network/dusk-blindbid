// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Bid data structure

use super::BidGenerationError;
use anyhow::{Error, Result};
use dusk_pki::{Ownable, StealthAddress};
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::sponge::sponge_hash;
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Debug)]
pub struct Bid {
    // b_enc (encrypted value and blinder)
    pub encrypted_data: PoseidonCipher,
    // Nonce used by the cypher
    pub nonce: BlsScalar,
    // Stealth address of the bidder
    pub stealth_address: StealthAddress,
    // m
    pub hashed_secret: BlsScalar,
    // c (Pedersen Commitment)
    pub c: AffinePoint,
    // Elegibility timestamp
    pub elegibility_ts: BlsScalar,
    // Expiration timestamp
    pub expiration_ts: BlsScalar,
}

impl Ownable for Bid {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

impl Bid {
    pub fn new<R>(
        rng: &mut R,
        stealth_address: &StealthAddress,
        value: &JubJubScalar,
        secret: &AffinePoint,
        secret_k: BlsScalar,
        elegibility_ts: BlsScalar,
        expiration_ts: BlsScalar,
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
        };
        // Generate an empty Bid and fill it with the correct values
        let mut bid = Bid {
            // Compute and add the `hashed_secret` to the Bid.
            hashed_secret: sponge_hash(&[secret_k]),
            elegibility_ts,
            expiration_ts,
            c: AffinePoint::default(),
            stealth_address: *stealth_address,
            encrypted_data: PoseidonCipher::default(),
            nonce: BlsScalar::default(),
        };

        bid.set_value(rng, value, secret);

        Ok(bid)
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
    pub(crate) fn generate_prover_id(
        &self,
        secret_k: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: BlsScalar,
        latest_consensus_step: BlsScalar,
    ) -> BlsScalar {
        sponge_hash(&[
            secret_k,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ])
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
