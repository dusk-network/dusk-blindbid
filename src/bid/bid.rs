// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Bid data structure

use super::BidGenerationError;
use anyhow::{Error, Result};
use dusk_pki::{Ownable, StealthAddress};
use dusk_plonk::jubjub::{
    AffinePoint, ExtendedPoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use kelvin::{ByteHash, Content, Sink, Source};
use poseidon252::cipher::PoseidonCipher;
use poseidon252::cipher::ENCRYPTED_DATA_SIZE;
use poseidon252::sponge::sponge::sponge_hash;
use poseidon252::StorageScalar;
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;
use std::io::{self, Read, Write};

/// Size of a serialized Bid.
/// The size is computed by adding up the `PoseidonCipher` size +
/// `StealthAddress` size + 1 `AffinePoint` + 4 `BlsScalar`s.
pub const BID_SIZE: usize = ENCRYPTED_DATA_SIZE + 64 + 32 * 5;

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

    // We cannot make this fn const since we need a mut buffer.
    // mutable references in const fn are unstable
    // see issue #57563 <https://github.com/rust-lang/rust/issues/57563>
    /// Given a Bid, return the byte-representation of it.
    pub fn to_bytes(&self) -> [u8; BID_SIZE] {
        let mut buf = [0u8; BID_SIZE];
        buf[0..ENCRYPTED_DATA_SIZE]
            .copy_from_slice(&self.encrypted_data.to_bytes());
        buf[ENCRYPTED_DATA_SIZE..128].copy_from_slice(&self.nonce.to_bytes());
        buf[128..192].copy_from_slice(&self.stealth_address.to_bytes());
        buf[192..224].copy_from_slice(&self.hashed_secret.to_bytes());
        buf[224..256].copy_from_slice(&self.c.to_bytes());
        buf[256..288].copy_from_slice(&self.elegibility_ts.to_bytes());
        buf[288..320].copy_from_slice(&self.expiration_ts.to_bytes());
        buf
    }

    // We cannot make this fn const since we need a mut buffer.
    // mutable references in const fn are unstable
    // see issue #57563 <https://github.com/rust-lang/rust/issues/57563>
    /// Given the byte-representation of a `Bid`, generate one instance of it.
    pub fn from_bytes(bytes: [u8; BID_SIZE]) -> io::Result<Bid> {
        let mut one_cipher = [0u8; ENCRYPTED_DATA_SIZE];
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];

        one_cipher[..].copy_from_slice(&bytes[0..ENCRYPTED_DATA_SIZE]);
        let encrypted_data =
            PoseidonCipher::from_bytes(&one_cipher).ok_or(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Could not recover PoseidonCipher from bytes"),
            ))?;
        one_scalar[..].copy_from_slice(&bytes[ENCRYPTED_DATA_SIZE..128]);
        let nonce = read_scalar(&one_scalar)?;

        one_stealth_address[..].copy_from_slice(&bytes[128..192]);
        let stealth_address = StealthAddress::from_bytes(&one_stealth_address)?;

        one_scalar[..].copy_from_slice(&bytes[192..224]);
        let hashed_secret = read_scalar(&one_scalar)?;

        one_scalar[..].copy_from_slice(&bytes[224..256]);
        let c = read_jubjub_affine(&one_scalar)?;

        one_scalar[..].copy_from_slice(&bytes[256..288]);
        let elegibility_ts = read_scalar(&one_scalar)?;

        one_scalar[..].copy_from_slice(&bytes[288..320]);
        let expiration_ts = read_scalar(&one_scalar)?;

        Ok(Bid {
            encrypted_data,
            nonce,
            stealth_address,
            hashed_secret,
            c,
            elegibility_ts,
            expiration_ts,
        })
    }

    pub fn hash(&self) -> BlsScalar {
        sponge_hash(
            self.encrypted_data
                .cipher()
                .iter()
                .chain(
                    [
                        self.nonce,
                        self.hashed_secret,
                        self.elegibility_ts,
                        self.expiration_ts,
                    ]
                    .iter(),
                )
                .chain(self.stealth_address.R().to_hash_inputs().iter())
                .chain(self.stealth_address.pk_r().to_hash_inputs().iter())
                .chain(ExtendedPoint::from(self.c).to_hash_inputs().iter())
                .map(|s| *s)
                .collect::<Vec<BlsScalar>>()
                .as_slice(),
        )
    }
}

impl Read for Bid {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = io::BufWriter::new(&mut buf[..]);
        let mut n = 0;

        n += buf.write(&self.encrypted_data.to_bytes())?;
        n += buf.write(&self.nonce.to_bytes())?;
        n += buf.write(&self.stealth_address.to_bytes())?;
        n += buf.write(&self.hashed_secret.to_bytes())?;
        n += buf.write(&self.c.to_bytes())?;
        n += buf.write(&self.elegibility_ts.to_bytes())?;
        n += buf.write(&self.expiration_ts.to_bytes())?;

        buf.flush()?;
        Ok(n)
    }
}

fn read_scalar(one_scalar: &[u8; 32]) -> io::Result<BlsScalar> {
    let possible_scalar = BlsScalar::from_bytes(&one_scalar);
    if possible_scalar.is_none().into() {
        return Err(io::ErrorKind::InvalidData)?;
    };
    Ok(possible_scalar.unwrap())
}

fn read_jubjub_affine(one_point: &[u8; 32]) -> io::Result<AffinePoint> {
    let possible_scalar = AffinePoint::from_bytes(*one_point);
    if possible_scalar.is_none().into() {
        return Err(io::ErrorKind::InvalidData)?;
    };
    Ok(possible_scalar.unwrap())
}

impl Write for Bid {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = io::BufReader::new(&buf[..]);

        let mut one_cipher = [0u8; 96];
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];

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
            StealthAddress::from_bytes(&one_stealth_address)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.hashed_secret = read_scalar(&one_scalar)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.c = read_jubjub_affine(&one_scalar)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.elegibility_ts = read_scalar(&one_scalar)?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.expiration_ts = read_scalar(&one_scalar)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<H: ByteHash> Content<H> for Bid {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        sink.write_all(&self.encrypted_data.to_bytes())?;
        sink.write_all(&self.nonce.to_bytes())?;
        sink.write_all(&self.stealth_address.to_bytes())?;
        sink.write_all(&self.hashed_secret.to_bytes())?;
        sink.write_all(&self.c.to_bytes())?;
        sink.write_all(&self.elegibility_ts.to_bytes())?;
        sink.write_all(&self.expiration_ts.to_bytes())?;
        Ok(())
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];

        let mut encrypted_data_cipher = [0u8; ENCRYPTED_DATA_SIZE];
        source.read_exact(&mut encrypted_data_cipher)?;
        let encrypted_data = PoseidonCipher::from_bytes(&encrypted_data_cipher)
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Could not recover PoseidonCipher from bytes"),
            ))?;

        source.read_exact(&mut one_scalar)?;
        let nonce = read_scalar(&one_scalar)?;

        source.read_exact(&mut one_stealth_address)?;
        let stealth_address = StealthAddress::try_from(&one_stealth_address)?;

        source.read_exact(&mut one_scalar)?;
        let hashed_secret = read_scalar(&one_scalar)?;

        source.read_exact(&mut one_scalar)?;
        let commitment = read_jubjub_affine(&one_scalar)?;

        source.read_exact(&mut one_scalar)?;
        let elegibility_ts = read_scalar(&one_scalar)?;

        source.read_exact(&mut one_scalar)?;
        let expiration_ts = read_scalar(&one_scalar)?;

        Ok(Bid {
            encrypted_data,
            nonce,
            stealth_address,
            hashed_secret,
            c: commitment,
            elegibility_ts,
            expiration_ts,
        })
    }
}

impl<'a> From<&'a Bid> for StorageScalar {
    fn from(bid: &'a Bid) -> StorageScalar {
        StorageScalar(bid.hash())
    }
}
