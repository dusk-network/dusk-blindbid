// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bid data structure

use crate::errors::BlindBidError;
#[cfg(feature = "canon")]
use canonical::{Canon, Store};
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    JubJubAffine, JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_pki::{Ownable, StealthAddress};
use poseidon252::sponge::sponge::sponge_hash;
use poseidon252::{cipher::PoseidonCipher, tree::PoseidonLeaf};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use std::io::{self, Read, Write};

/// Size of a serialized Bid.
/// The size is computed by adding up the `PoseidonCipher` size +
/// `StealthAddress` size + 1 `JubJubAffine` + 2 `BlsScalar`s + 3 u64's.
pub const BID_SIZE: usize =
    PoseidonCipher::cipher_size_bytes() + 64 + 32 * 3 + 8 * 3;

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
        secret: &JubJubAffine,
    ) -> Result<(JubJubScalar, JubJubScalar), BlindBidError> {
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
            .map_err(|_| BlindBidError::WrongSecretProvided)
    }

    // We cannot make this fn const since we need a mut buffer.
    // mutable references in const fn are unstable
    // see issue #57563 <https://github.com/rust-lang/rust/issues/57563>
    /// Given a Bid, return the byte-representation of it.
    pub fn to_bytes(&self) -> [u8; BID_SIZE] {
        let mut buf = [0u8; BID_SIZE];
        buf[0..PoseidonCipher::cipher_size_bytes()]
            .copy_from_slice(&self.encrypted_data.to_bytes());
        buf[PoseidonCipher::cipher_size_bytes()..128]
            .copy_from_slice(&self.nonce.to_bytes());
        buf[128..192].copy_from_slice(&self.stealth_address.to_bytes());
        buf[192..224].copy_from_slice(&self.hashed_secret.to_bytes());
        buf[224..256].copy_from_slice(&self.c.to_bytes());
        buf[256..264].copy_from_slice(&self.eligibility.to_le_bytes());
        buf[264..272].copy_from_slice(&self.expiration.to_le_bytes());
        buf[272..BID_SIZE].copy_from_slice(&self.pos.to_le_bytes());
        buf
    }

    // We cannot make this fn const since we need a mut buffer.
    // mutable references in const fn are unstable
    // see issue #57563 <https://github.com/rust-lang/rust/issues/57563>
    /// Given the byte-representation of a `Bid`, generate one instance of it.
    pub fn from_bytes(bytes: [u8; BID_SIZE]) -> Result<Bid, BlindBidError> {
        let mut one_cipher = [0u8; PoseidonCipher::cipher_size_bytes()];
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];
        let mut one_u64 = [0u8; 8];

        one_cipher[..]
            .copy_from_slice(&bytes[0..PoseidonCipher::cipher_size_bytes()]);
        let encrypted_data = PoseidonCipher::from_bytes(&one_cipher)
            .ok_or(BlindBidError::IOError)?;
        one_scalar[..]
            .copy_from_slice(&bytes[PoseidonCipher::cipher_size_bytes()..128]);
        let nonce = read_scalar(&one_scalar)?;

        one_stealth_address[..].copy_from_slice(&bytes[128..192]);
        let stealth_address = StealthAddress::from_bytes(&one_stealth_address);
        let stealth_address = match stealth_address {
            Ok(address) => Ok(address),
            Err(_) => Err(BlindBidError::IOError),
        }?;

        one_scalar[..].copy_from_slice(&bytes[192..224]);
        let hashed_secret = read_scalar(&one_scalar)?;

        one_scalar[..].copy_from_slice(&bytes[224..256]);
        let c = read_jubjub_affine(&one_scalar)?;

        one_u64[..].copy_from_slice(&bytes[256..264]);
        let eligibility = u64::from_le_bytes(one_u64);

        one_u64[..].copy_from_slice(&bytes[264..272]);
        let expiration = u64::from_le_bytes(one_u64);

        one_u64[..].copy_from_slice(&bytes[272..BID_SIZE]);
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

    /// Check if the bid is eligible for the provided block height
    pub fn eligible(&self, block_height: &u64) -> bool {
        &self.eligibility <= block_height && block_height <= &self.expiration
    }
}

impl PartialEq for Bid {
    fn eq(&self, other: &Self) -> bool {
        self.hash().eq(&other.hash())
    }
}

impl Eq for Bid {}

#[cfg(feature = "std")]
impl Read for Bid {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = io::BufWriter::new(&mut buf[..]);
        let mut n = 0;

        n += buf.write(&self.encrypted_data.to_bytes())?;
        n += buf.write(&self.nonce.to_bytes())?;
        n += buf.write(&self.stealth_address.to_bytes())?;
        n += buf.write(&self.hashed_secret.to_bytes())?;
        n += buf.write(&self.c.to_bytes())?;
        n += buf.write(&self.eligibility.to_le_bytes())?;
        n += buf.write(&self.expiration.to_le_bytes())?;
        n += buf.write(&self.pos.to_le_bytes())?;

        buf.flush()?;
        Ok(n)
    }
}

fn read_scalar(one_scalar: &[u8; 32]) -> Result<BlsScalar, BlindBidError> {
    let possible_scalar = BlsScalar::from_bytes(&one_scalar);
    if possible_scalar.is_none().into() {
        return Err(BlindBidError::IOError);
    };
    Ok(possible_scalar.unwrap())
}

fn read_jubjub_affine(
    one_point: &[u8; 32],
) -> Result<JubJubAffine, BlindBidError> {
    let possible_scalar = JubJubAffine::from_bytes(*one_point);
    if possible_scalar.is_none().into() {
        return Err(BlindBidError::IOError);
    };
    Ok(possible_scalar.unwrap())
}

#[cfg(feature = "std")]
impl Write for Bid {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = io::BufReader::new(&buf[..]);

        let mut one_cipher = [0u8; 96];
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];
        let mut one_u64 = [0u8; 8];

        let mut n = 0;

        buf.read_exact(&mut one_cipher)?;
        n += one_cipher.len();
        self.encrypted_data =
            PoseidonCipher::from_bytes(&one_cipher).ok_or(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Could not recover PoseidonCipher from bytes"),
            ))?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.nonce = read_scalar(&one_scalar)?;

        buf.read_exact(&mut one_stealth_address)?;
        n += one_stealth_address.len();
        self.stealth_address =
            match StealthAddress::from_bytes(&one_stealth_address) {
                Ok(address) => Ok(address),
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{:?}", e),
                )),
            }?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.hashed_secret = read_scalar(&one_scalar)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.c = read_jubjub_affine(&one_scalar)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.eligibility = u64::from_le_bytes(one_u64);

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.expiration = u64::from_le_bytes(one_u64);

        buf.read_exact(&mut one_u64)?;
        n += one_u64.len();
        self.pos = u64::from_le_bytes(one_u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
