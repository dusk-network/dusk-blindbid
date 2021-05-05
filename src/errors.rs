// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the BlindBid module

use core::fmt;
use dusk_bytes::Error as DuskBytesError;
use dusk_jubjub::JubJubScalar;
use dusk_poseidon::Error as PoseidonError;

#[derive(Debug)]
/// Compilation of the erros that blindbid procedures might end up producing.
pub enum BlindBidError {
    /// Error for the cases when we the score results are too large to
    /// fit inside a `Scalar`.
    InvalidScoreFieldsLen,
    /// Error that happens when you try to generate a `Score` for a `Bid`
    /// has already expired.
    ExpiredBid,
    /// Error for the cases when we the provided Bid value is bigger
    /// than the maximum allowed by the specs..
    MaximumBidValueExceeded {
        /// The maximum bid_value allowed
        max_val: JubJubScalar,
        /// The expected length
        found: JubJubScalar,
    },
    /// Error for the cases when we the provided Bid value is lower
    /// than the minimum allowed by the specs..
    MinimumBidValueUnreached {
        /// The minimum bid_value required
        min_val: JubJubScalar,
        /// The expected length
        found: JubJubScalar,
    },
    /// Error when there is a decrypt attempt with the wrong secret
    WrongSecretProvided,
    /// Invalid encoding/decoding
    IOError,
    /// Dusk-bytes serialization error
    SerializationError(DuskBytesError),
    /// Poseidon lib error
    PoseidonError(PoseidonError),
}

impl fmt::Display for BlindBidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bid Generation Error: {:?}", &self)
    }
}

#[cfg(feature = "std")]
impl From<BlindBidError> for std::io::Error {
    fn from(err: BlindBidError) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{:?}", err),
        )
    }
}

impl From<DuskBytesError> for BlindBidError {
    fn from(bytes_err: DuskBytesError) -> Self {
        Self::SerializationError(bytes_err)
    }
}

impl From<PoseidonError> for BlindBidError {
    fn from(poseidon_err: PoseidonError) -> Self {
        Self::PoseidonError(poseidon_err)
    }
}
