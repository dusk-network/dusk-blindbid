// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bid data structure

pub(crate) mod encoding;
pub(crate) mod score;
use crate::errors::BlindBidError;

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_pki::{Ownable, StealthAddress};
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge;
use rand_core::{CryptoRng, RngCore};
pub use score::Score;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Bid {
    /// Encrypted value and blinder.
    encrypted_data: PoseidonCipher,
    /// Nonce used by the cypher.
    nonce: BlsScalar,
    /// Stealth address of the bidder.
    stealth_address: StealthAddress,
    /// Hashed secret
    pub(crate) hashed_secret: BlsScalar,
    /// Commitment containing value & blinder fields hidden.
    pub(crate) c: JubJubAffine,
    /// Elegibility height
    pub(crate) eligibility: u64,
    /// Expiration height
    pub(crate) expiration: u64,
    /// Position of the Bid in the Tree where it is stored.
    pub(crate) pos: u64,
}

impl Borrow<u64> for Bid {
    fn borrow(&self) -> &u64 {
        &self.pos
    }
}

impl Ownable for Bid {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

impl PartialEq for Bid {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

impl Eq for Bid {}

// This needs to be between braces since const fn calls passed as const_generics
// params aren't perfectly supported yet.
impl
    Serializable<
        {
            PoseidonCipher::SIZE
                + StealthAddress::SIZE
                + 2 * BlsScalar::SIZE
                + JubJubAffine::SIZE
                + 8 * 3
        },
    > for Bid
{
    type Error = dusk_bytes::Error;

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Bid, Self::Error> {
        let mut buffer = &buf[..];
        let encrypted_data = PoseidonCipher::from_reader(&mut buffer)?;
        let nonce = BlsScalar::from_reader(&mut buffer)?;
        let stealth_address = StealthAddress::from_reader(&mut buffer)?;
        let hashed_secret = BlsScalar::from_reader(&mut buffer)?;
        let c = JubJubAffine::from_reader(&mut buffer)?;
        let eligibility = u64::from_reader(&mut buffer)?;
        let expiration = u64::from_reader(&mut buffer)?;
        let pos = u64::from_reader(&mut buffer)?;

        Ok(Bid {
            encrypted_data,
            nonce,
            stealth_address,
            hashed_secret,
            c,
            eligibility,
            expiration,
            pos,
        })
    }

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.encrypted_data.to_bytes());
        writer.write(&self.nonce.to_bytes());
        writer.write(&self.stealth_address.to_bytes());
        writer.write(&self.hashed_secret.to_bytes());
        writer.write(&self.c.to_bytes());
        writer.write(&self.eligibility.to_bytes());
        writer.write(&self.expiration.to_bytes());
        writer.write(&self.pos.to_bytes());
        buf
    }
}

impl Bid {
    /// Generates a new [Bid](self::Bid) from a rng source plus it's fields.  
    pub fn new<R>(
        rng: &mut R,
        stealth_address: &StealthAddress,
        value: &JubJubScalar,
        secret: &JubJubAffine,
        secret_k: BlsScalar,
        eligibility: u64,
        expiration: u64,
    ) -> Result<Self, BlindBidError>
    where
        R: RngCore + CryptoRng,
    {
        // Check if the bid_value is in the correct range, otherways, fail.
        match (
            value.reduce() > crate::V_MAX.reduce(),
            value.reduce() < crate::V_MIN.reduce(),
        ) {
            (true, false) => {
                return Err(BlindBidError::MaximumBidValueExceeded {
                    max_val: crate::V_MAX,
                    found: *value,
                })?;
            }
            (false, true) => {
                return Err(BlindBidError::MinimumBidValueUnreached {
                    min_val: crate::V_MIN,
                    found: *value,
                });
            }
            (false, false) => (),
            (_, _) => unreachable!(),
        };
        // Generate an empty Bid and fill it with the correct values
        let mut bid = Bid {
            // Compute and add the `hashed_secret` to the Bid.
            hashed_secret: sponge::hash(&[secret_k]),
            eligibility,
            expiration,
            c: JubJubAffine::default(),
            stealth_address: *stealth_address,
            encrypted_data: PoseidonCipher::default(),
            nonce: BlsScalar::default(),
            pos: 0u64,
        };

        bid.set_value(rng, value, secret);

        Ok(bid)
    }

    /// Returns the `encrypted_data` field of the [Bid](self::Bid).
    pub fn encrypted_data(&self) -> PoseidonCipher {
        self.encrypted_data
    }

    /// Returns the `nonce` field of the [Bid](self::Bid).
    pub fn nonce(&self) -> BlsScalar {
        self.nonce
    }

    /// Returns the `hashed_secret` field of the [Bid](self::Bid).
    pub fn hashed_secret(&self) -> BlsScalar {
        self.hashed_secret
    }

    /// Returns the `commitment` field of the [Bid](self::Bid).
    pub fn commitment(&self) -> JubJubAffine {
        self.c
    }

    /// Returns the `eligibility` field of the [Bid](self::Bid).
    pub fn eligibility(&self) -> u64 {
        self.eligibility
    }

    /// Returns the `expiration` field of the [Bid](self::Bid).
    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    /// Returns the `pos` field of the [Bid](self::Bid).
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Returns a mutable ref pointing to the `pos` field of the
    /// [Bid](self::Bid).
    pub fn set_pos(&mut self) -> &mut u64 {
        &mut self.pos
    }

    /// One-time prover-id is stated to be `H(secret_k, sigma^s, k^t, k^s)`.
    ///
    /// The function performs the sponge_hash techniqe using poseidon to
    /// get the one-time prover_id and sets it in the Bid.
    pub fn generate_prover_id(
        &self,
        secret_k: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: BlsScalar,
        latest_consensus_step: BlsScalar,
    ) -> BlsScalar {
        sponge::hash(&[
            secret_k,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ])
    }

    /// Decrypt the underlying data provided the secret of the bidder and return
    /// a tuple containing the value and the blinder fields.
    pub fn decrypt_data(
        &self,
        secret: &JubJubAffine,
    ) -> Result<(JubJubScalar, JubJubScalar), BlindBidError> {
        self.encrypted_data
            .decrypt(secret, &self.nonce)
            .map(|message| {
                let value = message[0];
                let blinder = message[1];

                let value =
                    JubJubScalar::from_raw(*value.reduce().internal_repr());
                let blinder =
                    JubJubScalar::from_raw(*blinder.reduce().internal_repr());

                (value, blinder)
            })
            .map_err(|_| BlindBidError::WrongSecretProvided)
    }

    pub(crate) fn set_value<R>(
        &mut self,
        rng: &mut R,
        value: &JubJubScalar,
        secret: &JubJubAffine,
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

        self.c = JubJubAffine::from(
            &(GENERATOR_EXTENDED * value)
                + &(GENERATOR_NUMS_EXTENDED * blinder),
        );
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod bid_serialization {
    use super::*;
    use crate::{V_RAW_MAX, V_RAW_MIN};
    use dusk_pki::{PublicSpendKey, SecretSpendKey};
    use rand::Rng;

    #[test]
    fn bid_serialization_roundtrip() {
        let bid = {
            let mut rng = rand::thread_rng();
            let pk_r = PublicSpendKey::from(SecretSpendKey::new(
                JubJubScalar::one(),
                -JubJubScalar::one(),
            ));
            let secret_k = BlsScalar::one();
            let secret = JubJubScalar::one();
            let stealth_addr = pk_r.gen_stealth_address(&secret);
            let secret = GENERATOR_EXTENDED * secret;
            let value: u64 =
                (&mut rand::thread_rng()).gen_range(V_RAW_MIN, V_RAW_MAX);
            let value = JubJubScalar::from(value);
            // Set the timestamps as the max values so the proofs do not fail
            // for them (never expired or non-elegible).
            let elegibility_ts = u64::MAX;
            let expiration_ts = u64::MAX;

            Bid::new(
                &mut rng,
                &stealth_addr,
                &value,
                &secret.into(),
                secret_k,
                elegibility_ts,
                expiration_ts,
            )
            .expect("Bid creation error")
        };

        let bid_bytes = bid.to_bytes();
        let bid_from_bytes =
            Bid::from_bytes(&bid_bytes).expect("Invalid roundtrip");
        assert_eq!(bid, bid_from_bytes)
    }
}
