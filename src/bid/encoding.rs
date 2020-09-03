// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//!BlsScalar Encoding module for Bid structure.
//!
//! See: https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L

use super::Bid;
use dusk_plonk::prelude::*;
use poseidon252::{sponge::sponge::*, StorageScalar};

// 1. Generate the type_fields Scalar Id:
// Type 1 will be BlsScalar
// Type 2 will be JubJubScalar
// Type 3 will be JubJubAffine coordinates tuple
// Type 4 will be u32
// Type 5 will be PoseidonCipher
// Byte-types are treated in Little Endian.
// The purpose of this set of flags is to avoid collision between different structures
const TYPE_FIELDS: [u8; 32] = *b"53313110000000000000000000000000";

/// Encodes a `StorageBid` in a `StorageScalar` form by applying the correct
/// encoding methods and collapsing it into a `StorageScalar` which can be then
/// stored inside of a `kelvin` tree data structure.
impl Into<StorageScalar> for Bid {
    fn into(self) -> StorageScalar {
        // Generate an empty vector of `Scalar` which will store the
        // representation of all of the `Bid` elements.
        let mut words_deposit = Vec::new();
        // Note that the merkle_tree_root is not used since we can't pre-compute
        // it. Therefore, any field that relies on it to be computed isn't
        // neither used to obtain this encoded form.

        // Safe unwrap here.
        let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();
        words_deposit.push(type_fields);

        // 2. Encode each word.
        // Push cipher as scalars.
        words_deposit.extend_from_slice(self.encrypted_data.cipher());

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.stealth_address.pk_r().get_x());
        words_deposit.push(self.stealth_address.pk_r().get_y());

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.stealth_address.R().get_x());
        words_deposit.push(self.stealth_address.R().get_y());

        words_deposit.push(self.hashed_secret);

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.c.get_x());
        words_deposit.push(self.c.get_y());
        // Push the timestamps of the Bid
        words_deposit.push(self.elegibility_ts);
        words_deposit.push(self.expiration_ts);

        // Once all of the words are translated as `Scalar` and stored
        // correctly, apply the Poseidon sponge hash function to obtain
        // the encoded form of the `Bid`.
        StorageScalar(sponge_hash(&words_deposit))
    }
}

impl Bid {
    /// Applies a preimage_gadget to the `StorageBid` fields hashing them and
    /// constraining the result of the sponge hash to the real/expected
    /// `StorageBid` encoded value expressed as `Scalar/StorageScalar`.
    ///
    /// The expected encoded value is a Public Input for this circuit.
    /// Appart from that, the preimage_gadget hashing result is returned.
    pub(crate) fn preimage_gadget(
        &self,
        composer: &mut StandardComposer,
    ) -> Variable {
        // This field represents the types of the inputs and has to be the same
        // as the default one.
        // It has been already checked that it's safe to unwrap here since the
        // value fits correctly in a `BlsScalar`.
        let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();

        // Add to the composer the values required for the preimage.
        let mut messages: Vec<Variable> = vec![];
        messages.push(composer.add_input(type_fields));
        // Push both JubJubAffine coordinates as a Scalar.
        self.encrypted_data.cipher().iter().for_each(|c| {
            let c = composer.add_input(*c);
            messages.push(c);
        });

        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.stealth_address.pk_r().get_x()));
        messages.push(composer.add_input(self.stealth_address.pk_r().get_y()));
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.stealth_address.R().get_x()));
        messages.push(composer.add_input(self.stealth_address.R().get_y()));
        messages.push(composer.add_input(self.hashed_secret));
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.c.get_x()));
        messages.push(composer.add_input(self.c.get_y()));
        // Add elebility & expiration timestamps.
        messages.push(composer.add_input(self.elegibility_ts));
        messages.push(composer.add_input(self.expiration_ts));

        // Perform the sponge_hash inside of the Constraint System
        let storage_bid_hash = sponge_hash_gadget(composer, &messages);
        // Constraint the hash to be equal to the real one
        let real_hash: StorageScalar = self.clone().into();
        let real_hash: BlsScalar = real_hash.into();
        composer.constrain_to_constant(
            storage_bid_hash,
            BlsScalar::zero(),
            -real_hash,
        );
        storage_bid_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Error, Result};
    use dusk_pki::StealthAddress;
    use dusk_plonk::jubjub::{AffinePoint, GENERATOR_EXTENDED};
    use rand::Rng;
    use std::convert::TryFrom;

    fn random_bid(secret: &JubJubScalar) -> Result<Bid, Error> {
        let mut rng = rand::thread_rng();

        let secret_k = BlsScalar::random(&mut rng);
        let secret = GENERATOR_EXTENDED * secret;
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);
        let pk_r = AffinePoint::from(
            GENERATOR_EXTENDED * JubJubScalar::random(&mut rng),
        );
        let R = AffinePoint::from(
            GENERATOR_EXTENDED * JubJubScalar::random(&mut rng),
        );
        let mut stealth_addr_buff = [0u8; 64];
        stealth_addr_buff[0..32].copy_from_slice(&pk_r.to_bytes()[..]);
        stealth_addr_buff[32..].copy_from_slice(&R.to_bytes()[..]);
        let stealth_addr = StealthAddress::try_from(&stealth_addr_buff)?;
        let elegibility_ts = BlsScalar::random(&mut rng);
        let expiration_ts = BlsScalar::random(&mut rng);

        Bid::new(
            &mut rng,
            &stealth_addr,
            &value,
            &secret.into(),
            secret_k,
            elegibility_ts,
            expiration_ts,
        )
    }

    #[ignore]
    #[test]
    fn test_word_padding() {
        // This cannot be tested until we don't get propper test vectors from
        // the research side.
    }

    #[test]
    fn bid_preimage_gadget() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret)?;

        // Proving
        let mut prover = Prover::new(b"testing");
        bid.preimage_gadget(prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        bid.preimage_gadget(verifier.mut_cs());
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        verifier.verify(&proof, &vk, &pi)
    }
}
