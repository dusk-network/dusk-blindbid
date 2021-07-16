// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The bid module contains all of the structures & logic that the bidder needs
//! in order to participate in the bidding process inside the Dusk blockchain
//! consensus. In particular, provides these core functionalities among others.
//! - Generation of a prover ID.
//! - Generation of a Score.
//! - Generation of a Proof of BlindBid.

pub(crate) mod encoding;
pub(crate) mod score;

#[cfg(feature = "canon")]
use canonical_derive::Canon;

use crate::errors::BlindBidError;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_pki::{Ownable, PublicSpendKey, StealthAddress};
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge;
use phoenix_core::Message;
pub use score::Score;

/// The Bid structure contains all of the logic and information needed to be
/// able to participate in the Dusk consensus lottery through the bidding
/// process. It allows the user to generate a random Bid with which will be able
/// to generate a [`Score`] and participate in leader election
/// process for this consensus round iteration. In particular, a Bid provides
/// these core functionalities among others.
/// - Generation of a Prover ID.
/// - Generation of a Score.
///
/// It is always initialized randomly, and any trick to cheat on it's
/// initialization/construction will resume in a failure in the BindBidProof
/// verification.
///
/// The Bid is also designed to be stored within a
/// [PoseidonTree](dusk_poseidon::tree::PoseidonTree). Although it's not
/// responsability of this crate to provide such implementation. To make that
/// happen, make sure to implement
/// [PoseidonLeaf](dusk_poseidon::tree::PoseidonLeaf) trait for it or a wrapper
/// structure.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Bid {
    pub(crate) message: Message,
    /// Stealth address of the bidder.
    stealth_address: StealthAddress,
    /// Hashed secret (m)
    pub(crate) hashed_secret: BlsScalar,
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
        { Message::SIZE + StealthAddress::SIZE + BlsScalar::SIZE + 8 * 3 },
    > for Bid
{
    type Error = dusk_bytes::Error;

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Bid, Self::Error> {
        let mut buffer = &buf[..];
        let message = Message::from_reader(&mut buffer)?;
        let stealth_address = StealthAddress::from_reader(&mut buffer)?;
        let hashed_secret = BlsScalar::from_reader(&mut buffer)?;
        let eligibility = u64::from_reader(&mut buffer)?;
        let expiration = u64::from_reader(&mut buffer)?;
        let pos = u64::from_reader(&mut buffer)?;

        Ok(Bid {
            message,
            stealth_address,
            hashed_secret,
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
        writer.write(&self.message.to_bytes());
        writer.write(&self.stealth_address.to_bytes());
        writer.write(&self.hashed_secret.to_bytes());
        writer.write(&self.eligibility.to_bytes());
        writer.write(&self.expiration.to_bytes());
        writer.write(&self.pos.to_bytes());
        buf
    }
}

impl Bid {
    /// Generate a new Bid from a [`Message`], the hashed secret(m) and a
    /// [`StealthAddress`].
    pub fn new(
        message: Message,
        hashed_secret: BlsScalar,
        addr: StealthAddress,
        eligibility: u64,
        expiration: u64,
    ) -> Bid {
        Bid {
            message,
            hashed_secret,
            stealth_address: addr,
            eligibility,
            expiration,
            pos: 0u64,
        }
    }

    /// Returns the `message` field of the Bid.
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Returns the raw cipher data from the [`PoseidonCipher`] located inside
    /// of the [`Message`] field of the Bid.
    pub const fn encrypted_data(
        &self,
    ) -> &[BlsScalar; PoseidonCipher::cipher_size()] {
        self.message.cipher()
    }

    /// Returns the `nonce` field of the Bid.
    pub const fn nonce(&self) -> &BlsScalar {
        &self.message.nonce()
    }

    /// Returns the `hashed_secret` field of the Bid.
    pub const fn hashed_secret(&self) -> &BlsScalar {
        &self.hashed_secret
    }

    /// Returns the `commitment` field of the Bid.
    pub const fn commitment(&self) -> &JubJubExtended {
        self.message.value_commitment()
    }

    /// Returns the `eligibility` field of the Bid.
    pub const fn eligibility(&self) -> &u64 {
        &self.eligibility
    }

    /// Sets a new value for the eligibility of the Bid.
    pub fn set_eligibility(&mut self, new_eligibility: u64) {
        self.eligibility = new_eligibility;
    }

    /// Returns the `expiration` field of the Bid.
    pub const fn expiration(&self) -> &u64 {
        &self.expiration
    }

    /// Returns a mutable ref pointing to the `pos` field of the
    /// Bid.
    pub fn extend_expiration(&mut self, extension: u64) {
        self.expiration += extension;
    }

    /// Returns the `pos` field of the Bid.
    pub const fn pos(&self) -> &u64 {
        &self.pos
    }

    /// Sets a new value for the position of the Bid.
    pub fn set_pos(&mut self, new_pos: u64) {
        self.pos = new_pos;
    }

    /// Performs the [sponge_hash](sponge::hash) techniqe using poseidon to
    /// compute the one-time prover_id that corresponds to a Bid in an specific
    /// point of the consensus which is determinated by:
    /// - consensus_round_seed (sigma^s)
    /// - latest_consensus_round (k^t)
    /// - latest_consensus_step (k^s)
    /// One-time prover-id is stated to be `H(bid.secret_k, sigma^s, k^t, k^s)`.
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

    /// Provided the secret, decripts the data stored inside the
    /// [cipher](PoseidonCipher) returning a tuple that contains
    /// the value at stake in the bid and the blinder data which are the two
    /// values used to generate the bid commitment.
    pub fn decrypt_data(
        &self,
        secret: &JubJubScalar,
        psk: &PublicSpendKey,
    ) -> Result<(JubJubScalar, JubJubScalar), BlindBidError> {
        self.message
            .decrypt(secret, psk)
            .map_err(|_| BlindBidError::WrongSecretProvided)
            .map(|(value, blinder)| (JubJubScalar::from(value), blinder))
    }
}

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
            let psk = PublicSpendKey::from(SecretSpendKey::new(
                JubJubScalar::one(),
                -JubJubScalar::one(),
            ));
            let secret_k = BlsScalar::one();
            let secret = JubJubScalar::one();
            let value: u64 =
                (&mut rand::thread_rng()).gen_range(V_RAW_MIN..V_RAW_MAX);
            // Set the timestamps as the max values so the proofs do not fail
            // for them (never expired or non-elegible).
            let elegibility_ts = u64::MAX;
            let expiration_ts = u64::MAX;

            Bid::new(
                Message::new(&mut rng, &secret, &psk, value),
                secret_k,
                psk.gen_stealth_address(&secret),
                elegibility_ts,
                expiration_ts,
            )
        };

        let bid_bytes = bid.to_bytes();
        let bid_from_bytes =
            Bid::from_bytes(&bid_bytes).expect("Invalid roundtrip");
        assert_eq!(bid, bid_from_bytes)
    }
}
