// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Encoding module for Bid structure.
//! See: <https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L>

use super::Bid;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_poseidon::sponge;

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
const TYPE_FIELDS: [u8; 32] = *b"53313116000000000000000000000000";

impl Bid {
    /// Return the Bid as a set of "hasheable" parameters which is directly
    /// digestible by the Poseidon sponge hash fn.
    pub fn as_hash_inputs(&self) -> [BlsScalar; 13] {
        // Generate an empty vector of `Scalar` which will store the
        // representation of all of the `Bid` elements.
        let mut words_deposit = [BlsScalar::zero(); 13];
        // Note that the merkle_tree_root is not used since we can't pre-compute
        // it. Therefore, any field that relies on it to be computed isn't
        // neither used to obtain this encoded form.

        // Safe unwrap here.
        let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();
        words_deposit[0] = type_fields;

        // 2. Encode each word.
        // Push cipher as scalars.
        words_deposit[1] = self.encrypted_data.cipher()[0];
        words_deposit[2] = self.encrypted_data.cipher()[1];

        // Push both JubJubAffine coordinates as a Scalar.
        {
            let tmp = self.stealth_address.pk_r().as_ref().to_hash_inputs();
            words_deposit[3] = tmp[0];
            words_deposit[4] = tmp[1];
        }
        // Push both JubJubAffine coordinates as a Scalar.
        {
            let tmp = self.stealth_address.R().to_hash_inputs();
            words_deposit[5] = tmp[0];
            words_deposit[6] = tmp[1];
        }

        words_deposit[7] = self.hashed_secret;

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit[8] = self.c.get_x();
        words_deposit[9] = self.c.get_y();
        // Push the timestamps of the Bid
        words_deposit[10] = BlsScalar::from(self.eligibility);
        words_deposit[11] = BlsScalar::from(self.expiration);
        words_deposit[12] = BlsScalar::from(self.pos);

        words_deposit
    }

    /// Calculate the one-way BlsScalar representation of the Bid
    pub fn hash(&self) -> BlsScalar {
        // Set the Bid parameters on a "hasheable" way to be digested
        // by the poseidon sponge hash.
        // Once all of the words are translated as `Scalar` and stored
        // correctly, apply the Poseidon sponge hash function to obtain
        // the encoded form of the `Bid`.
        sponge::hash(&self.as_hash_inputs())
    }
}

impl Into<BlsScalar> for &Bid {
    fn into(self) -> BlsScalar {
        self.hash()
    }
}

impl Into<BlsScalar> for Bid {
    fn into(self) -> BlsScalar {
        (&self).into()
    }
}
