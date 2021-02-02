// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bid data structure

use crate::errors::BlindBidError;
#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(all(feature = "canon", feature = "std"))]
use canonical::Store;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{
    JubJubAffine, JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_pki::{Ownable, StealthAddress};
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::hash as sponge_hash;
#[cfg(feature = "std")]
use poseidon252::tree::PoseidonLeaf;
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
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
    pub c: JubJubAffine,
    // Elegibility timestamp
    pub eligibility: u64,
    // Expiration timestamp
    pub expiration: u64,
    // Position of the Bid in the BidTree
    pub pos: u64,
}

impl Ownable for Bid {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

impl Borrow<u64> for Bid {
    fn borrow(&self) -> &u64 {
        &self.pos
    }
}

impl PartialEq for Bid {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

// This needs to be between braces since const fn calls passed as const_generics
// params aren't perfectly supported yet.
impl Serializable<{ Bid::serialized_size() }> for Bid {
    type Error = BlindBidError;

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Bid, Self::Error> {
        let mut one_cipher = [0u8; PoseidonCipher::cipher_size_bytes()];
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];
        let mut one_u64 = [0u8; 8];

        one_cipher[..]
            .copy_from_slice(&buf[0..PoseidonCipher::cipher_size_bytes()]);
        let encrypted_data = PoseidonCipher::from_bytes(&one_cipher)?;

        one_scalar[..]
            .copy_from_slice(&buf[PoseidonCipher::cipher_size_bytes()..128]);
        let nonce = BlsScalar::from_bytes(&one_scalar)?;

        one_stealth_address[..].copy_from_slice(&buf[128..192]);
        let stealth_address = StealthAddress::from_bytes(&one_stealth_address)?;

        one_scalar[..].copy_from_slice(&buf[192..224]);
        let hashed_secret = BlsScalar::from_bytes(&one_scalar)?;

        one_scalar[..].copy_from_slice(&buf[224..256]);
        let c = JubJubAffine::from_bytes(&one_scalar)?;

        one_u64[..].copy_from_slice(&buf[256..264]);
        let eligibility = u64::from_le_bytes(one_u64);

        one_u64[..].copy_from_slice(&buf[264..272]);
        let expiration = u64::from_le_bytes(one_u64);

        one_u64[..].copy_from_slice(&buf[272..Bid::serialized_size()]);
        let pos = u64::from_le_bytes(one_u64);

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

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..PoseidonCipher::cipher_size_bytes()]
            .copy_from_slice(&self.encrypted_data.to_bytes());
        buf[PoseidonCipher::cipher_size_bytes()..128]
            .copy_from_slice(&self.nonce.to_bytes());
        buf[128..192].copy_from_slice(&self.stealth_address.to_bytes());
        buf[192..224].copy_from_slice(&self.hashed_secret.to_bytes());
        buf[224..256].copy_from_slice(&self.c.to_bytes());
        buf[256..264].copy_from_slice(&self.eligibility.to_le_bytes());
        buf[264..272].copy_from_slice(&self.expiration.to_le_bytes());
        buf[272..Bid::serialized_size()]
            .copy_from_slice(&self.pos.to_le_bytes());
        buf
    }
}

impl Eq for Bid {}

// TODO: Remove probably. Ask team.
#[cfg(all(feature = "canon", feature = "std"))]
impl<S> PoseidonLeaf<S> for Bid
where
    S: Store,
{
    fn poseidon_hash(&self) -> BlsScalar {
        self.hash()
    }

    fn pos(&self) -> u64 {
        self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl Bid {
    /// Returns the serialized size of a Bid.
    pub const fn serialized_size() -> usize {
        PoseidonCipher::cipher_size_bytes() + 64 + 32 * 3 + 8 * 3
    }

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
            hashed_secret: sponge_hash(&[secret_k]),
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
        sponge_hash(&[
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
