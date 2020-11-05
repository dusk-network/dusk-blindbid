// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bid data structure

use super::{BidGenerationError, ZkBid};
use crate::{utils, V_MAX, V_MIN};
use anyhow::{anyhow, Error, Result};
#[cfg(feature = "canon")]
use canonical::{Canon, Store};
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_pki::{Ownable, StealthAddress};
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use poseidon252::cipher::{PoseidonCipher, ENCRYPTED_DATA_SIZE};
use poseidon252::sponge::sponge::sponge_hash;
#[cfg(feature = "canon")]
use poseidon252::tree::PoseidonLeaf;
use rand_core::{CryptoRng, RngCore};

/// Size of a serialized Bid.
/// The size is computed by adding up the `PoseidonCipher` size +
/// `StealthAddress` size + 1 `AffinePoint` + 4 `BlsScalar`s.
pub const BID_SIZE: usize = ENCRYPTED_DATA_SIZE + // poseidon cipher
    32 + // nonce
    64 + // stealth address
    32 + // hashed_secret
    32 + // c
    08 + // eligibility
    08 + // expiration
    08; // pos

// 1. Generate the type_fields Scalar Id:
// Type 1 will be BlsScalar
// Type 2 will be JubJubScalar
// Type 3 will be JubJubAffine coordinates tuple
// Type 4 will be u32
// Type 5 will be PoseidonCipher
// Type 6 will be u64
// Byte-types are treated in Little Endian.
// The purpose of this set of flags is to avoid collision between different
// structures
pub const TYPE_FIELDS: [u8; 32] = *b"53313666000000000000000000000000";

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Bid {
    /// b_enc (encrypted value and blinder)
    pub encrypted_data: PoseidonCipher,
    /// Nonce used by the cypher
    pub nonce: BlsScalar,
    /// Stealth address of the bidder
    pub stealth_address: StealthAddress,
    /// m
    pub hashed_secret: BlsScalar,
    /// c (Pedersen Commitment)
    pub c: AffinePoint,
    /// Elegibility timestamp
    pub eligibility: u64,
    /// Expiration timestamp
    pub expiration: u64,
    /// Position in the merkle tree
    pub pos: u64,
}

impl Ownable for Bid {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

#[cfg(feature = "canon")]
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

impl PartialEq for Bid {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}
impl Eq for Bid {}

impl Borrow<u64> for Bid {
    fn borrow(&self) -> &u64 {
        &self.expiration
    }
}

impl Bid {
    /// Create a new bid
    ///
    /// The internal value related attributes (encrypted data, nonce and
    /// commitment point) will be defined in function of the provided random
    /// number generator
    ///
    /// The position in the merkle tree will be defaulted to 0. It should be
    /// later set by the tree when the bid is appended
    pub fn new<R>(
        rng: &mut R,
        stealth_address: &StealthAddress,
        value: &JubJubScalar,
        secret: &AffinePoint,
        secret_k: BlsScalar,
        eligibility: u64,
        expiration: u64,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let value = value.reduce();

        // Value should be in range with the maximum and minimum allowed
        {
            if value < V_MIN.reduce() {
                return Err(BidGenerationError::MinimumBidValueUnreached {
                    min_val: V_MIN,
                    found: value,
                }
                .into());
            }

            if value > V_MAX.reduce() {
                return Err(BidGenerationError::MaximumBidValueExceeded {
                    max_val: V_MAX,
                    found: value,
                }
                .into());
            }
        }

        let mut bid = Bid {
            hashed_secret: sponge_hash(&[secret_k]),
            eligibility,
            expiration,
            c: AffinePoint::default(),
            stealth_address: *stealth_address,
            encrypted_data: PoseidonCipher::default(),
            nonce: BlsScalar::default(),
            pos: 0,
        };

        bid.set_value(rng, &value, secret);

        Ok(bid)
    }

    /// Set the value of the bid.
    ///
    /// Recalculate the blinder, nonce, encrypted data and commitment point
    /// according to the provided value
    pub fn set_value<R>(
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
    /// a tuple containing the value and the blinder
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

    /// Given a Bid, return the byte-representation of it.
    pub fn to_bytes(&self) -> [u8; BID_SIZE] {
        let mut buf = [0u8; BID_SIZE];

        buf[0..ENCRYPTED_DATA_SIZE]
            .copy_from_slice(&self.encrypted_data.to_bytes());
        buf[ENCRYPTED_DATA_SIZE..128].copy_from_slice(&self.nonce.to_bytes());
        buf[128..192].copy_from_slice(&self.stealth_address.to_bytes());
        buf[192..224].copy_from_slice(&self.hashed_secret.to_bytes());
        buf[224..256].copy_from_slice(&self.c.to_bytes());
        buf[256..264].copy_from_slice(&self.eligibility.to_le_bytes());
        buf[264..272].copy_from_slice(&self.expiration.to_le_bytes());
        buf[280..288].copy_from_slice(&self.pos.to_le_bytes());

        buf
    }

    /// Given the byte-representation of a `Bid`, generate one instance of it.
    pub fn from_bytes(bytes: [u8; BID_SIZE]) -> Result<Bid> {
        let mut cipher = [0u8; ENCRYPTED_DATA_SIZE];
        let mut scalar = [0u8; 32];
        let mut stealth_address = [0u8; 64];
        let mut number = [0u8; 8];

        cipher[..].copy_from_slice(&bytes[0..ENCRYPTED_DATA_SIZE]);
        let encrypted_data = PoseidonCipher::from_bytes(&cipher)
            .ok_or(anyhow!("Could not recover PoseidonCipher from bytes"))?;
        scalar.copy_from_slice(&bytes[ENCRYPTED_DATA_SIZE..128]);
        let nonce = utils::read_scalar(&scalar)?;

        stealth_address.copy_from_slice(&bytes[128..192]);
        let stealth_address = StealthAddress::from_bytes(&stealth_address)?;

        scalar.copy_from_slice(&bytes[192..224]);
        let hashed_secret = utils::read_scalar(&scalar)?;

        scalar.copy_from_slice(&bytes[224..256]);
        let c = utils::read_jubjub_affine(scalar)?;

        number.copy_from_slice(&bytes[256..264]);
        let eligibility = u64::from_le_bytes(number);

        number.copy_from_slice(&bytes[264..272]);
        let expiration = u64::from_le_bytes(number);

        number.copy_from_slice(&bytes[280..288]);
        let pos = u64::from_le_bytes(number);

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

    /// Check if the bid is eligible for the provided block height
    pub fn eligible(&self, block_height: u64) -> bool {
        self.eligibility <= block_height && block_height <= self.expiration
    }

    /// Poseidon hash of the bid
    #[allow(non_snake_case)]
    pub fn hash(&self) -> BlsScalar {
        let mut words_deposit = Vec::with_capacity(11);

        // Safe unwrap
        let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();
        words_deposit.push(type_fields);

        // 2. Encode each word.
        words_deposit.extend_from_slice(self.encrypted_data.cipher());

        let pk_r = self.stealth_address.pk_r().to_hash_inputs();
        words_deposit.extend_from_slice(pk_r.as_ref());

        let r = self.stealth_address.R().to_hash_inputs();
        words_deposit.extend_from_slice(r.as_ref());

        words_deposit.push(self.hashed_secret);
        words_deposit.push(self.c.get_x());
        words_deposit.push(self.c.get_y());
        words_deposit.push(BlsScalar::from(self.eligibility));
        words_deposit.push(BlsScalar::from(self.expiration));
        words_deposit.push(BlsScalar::from(self.pos));

        sponge_hash(&words_deposit)
    }

    pub fn zk(&self, composer: &mut StandardComposer) -> ZkBid {
        ZkBid::new(composer, &self)
    }
}
