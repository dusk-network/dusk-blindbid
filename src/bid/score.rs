// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Score generation module

#[cfg(feature = "canon")]
use canonical_derive::Canon;

#[cfg(feature = "std")]
use {
    crate::bid::{Bid, BlindBidError},
    dusk_jubjub::JubJubScalar,
    dusk_pki::PublicSpendKey,
    dusk_poseidon::sponge,
    num_bigint::BigUint,
    num_traits::{One, Zero},
};

use core::ops::Deref;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
/// The `Score` represents a "random" value obtained from the computations
/// based on blockchain data as well as [Bid](crate::Bid) data.
/// It derefs to it's value although the structure contains more fields which
/// are side-results of this computation needed to proof the correctness of the
/// Score generation process later on.
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Score {
    value: BlsScalar,
    y: BlsScalar,
    y_prime: BlsScalar,
    r1: BlsScalar,
    r2: BlsScalar,
}

impl Deref for Score {
    type Target = BlsScalar;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl AsRef<BlsScalar> for Score {
    fn as_ref(&self) -> &BlsScalar {
        &self.value
    }
}

impl Serializable<{ 5 * BlsScalar::SIZE }> for Score {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.as_ref().to_bytes());
        writer.write(&self.as_ref().to_bytes());
        writer.write(&self.as_ref().to_bytes());
        writer.write(&self.as_ref().to_bytes());
        writer.write(&self.as_ref().to_bytes());
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut buffer = &buf[..];
        Ok(Score {
            value: BlsScalar::from_reader(&mut buffer)?,
            y: BlsScalar::from_reader(&mut buffer)?,
            y_prime: BlsScalar::from_reader(&mut buffer)?,
            r1: BlsScalar::from_reader(&mut buffer)?,
            r2: BlsScalar::from_reader(&mut buffer)?,
        })
    }
}

impl Score {
    /// Returns the `r1` value of the `Score`.
    pub const fn r1(&self) -> &BlsScalar {
        &self.r1
    }
    /// Returns the `r2` value of the `Score`.
    pub const fn r2(&self) -> &BlsScalar {
        &self.r2
    }
    /// Returns the `y` value of the `Score`.
    pub const fn y(&self) -> &BlsScalar {
        &self.y
    }
    /// Returns the `y_prime` value of the `Score`.
    pub const fn y_prime(&self) -> &BlsScalar {
        &self.y_prime
    }
    /// Returns the value of the `Score`.
    pub const fn value(&self) -> &BlsScalar {
        &self.value
    }
}

impl Score {
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    /// Given a `Bid`, compute it's Score and return it.
    pub fn compute(
        bid: &Bid,
        secret: &JubJubScalar,
        psk: &PublicSpendKey,
        secret_k: BlsScalar,
        bid_tree_root: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: u64,
        latest_consensus_step: u64,
    ) -> Result<Score, BlindBidError> {
        if latest_consensus_round > bid.expiration {
            return Err(BlindBidError::ExpiredBid);
        };

        let latest_consensus_round = BlsScalar::from(latest_consensus_round);
        let latest_consensus_step = BlsScalar::from(latest_consensus_step);

        // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed,
        // latest_consensus_round, latest_consensus_step)`.
        let y = sponge::hash(&[
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ]);
        let (value, _) = bid.decrypt_data(secret, psk)?;

        // Truncate Y to left 128 bits and interpret the result as 128-bit
        // integer. Keep the right 128 bits as another integer (r1).
        let r1 = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
        let y_prime = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

        // Get the bid value outside of the modular field and treat it as
        // an integer.
        let bid_value = BigUint::from_bytes_le(&value.to_bytes());
        // Compute the final score
        let (f, r2) = match y_prime == BigUint::zero() {
            // If y' != 0 -> f = (bid_value * 2^128 / y')
            // r2 is assigned to the remainder of the division.
            false => {
                let num = bid_value * (BigUint::one() << 128);
                (&num / &y_prime, &num % &y_prime)
            }
            // If y' == 0 -> f = bid_value * 2^128
            // Since there's not any division, r2 is assigned to 0 since
            // there's not any remainder.
            true => (bid_value * (BigUint::one() << 128), BigUint::zero()),
        };

        // Get Scalars from the bigUints and return a `Score` if the conversions
        // could be correctly done.
        Ok(Score {
            value: biguint_to_scalar(f)?,
            y,
            y_prime: biguint_to_scalar(y_prime)?,
            r1: biguint_to_scalar(r1)?,
            r2: biguint_to_scalar(r2)?,
        })
    }
}

#[cfg(feature = "std")]
/// Given the y parameter, return the y' and it's inverse value.
fn biguint_to_scalar(biguint: BigUint) -> Result<BlsScalar, BlindBidError> {
    let mut bytes = [0u8; 32];
    let biguint_bytes = biguint.to_bytes_le();
    if biguint_bytes.len() > 32 {
        return Err(BlindBidError::InvalidScoreFieldsLen);
    };
    bytes[..biguint_bytes.len()].copy_from_slice(&biguint_bytes);
    // Due to the previous conditions, we can unwrap here safely.
    Ok(BlsScalar::from_bytes(&bytes).unwrap())
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biguint_scalar_conversion() {
        let rand_scalar = BlsScalar::random(&mut rand::thread_rng());
        let big_uint = BigUint::from_bytes_le(&rand_scalar.to_bytes());

        assert_eq!(
            biguint_to_scalar(big_uint).expect("BigUint conversion failed"),
            rand_scalar
        )
    }
}

#[cfg(test)]
mod score_serialization {
    use super::*;

    #[test]
    fn score_serialization_roundtrip() {
        let score = Score {
            value: BlsScalar::one(),
            y: BlsScalar::one(),
            y_prime: BlsScalar::one(),
            r1: BlsScalar::one(),
            r2: BlsScalar::one(),
        };

        let score_bytes = score.to_bytes();
        let score_from_bytes =
            Score::from_bytes(&score_bytes).expect("Invalid roundtrip");
        assert_eq!(score, score_from_bytes)
    }
}
