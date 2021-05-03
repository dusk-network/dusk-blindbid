// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Encoding module for Bid structure.
//! See: <https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L>

use super::Bid;
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_plonk::constraint_system::ecc::Point as PlonkPoint;
use dusk_plonk::prelude::*;
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

/// Hashes the internal Bid parameters using the Poseidon hash
/// function and the cannonical encoding for hashing returning a
/// Variable which contains the hash of the Bid.
pub(crate) fn preimage_gadget(
    composer: &mut StandardComposer,
    // TODO: We should switch to a different representation for this.
    // it can be a custom PoseidonCipherVariable structure or maybe
    // just a fixed len array of Variables.
    encrypted_data: (Variable, Variable),
    commitment: PlonkPoint,
    // (Pkr, R)
    stealth_addr: (PlonkPoint, PlonkPoint),
    hashed_secret: Variable,
    eligibility: Variable,
    expiration: Variable,
    pos: Variable,
) -> Variable {
    // This field represents the types of the inputs and has to be the same
    // as the default one.
    // It has been already checked that it's safe to unwrap here since the
    // value fits correctly in a `BlsScalar`.
    let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();

    // Add to the composer the values required for the preimage.
    let mut messages: Vec<Variable> = Vec::new();
    messages.push(composer.add_input(type_fields));
    // Push cipher as scalars.
    messages.push(encrypted_data.0);
    messages.push(encrypted_data.1);

    // Push both JubJubAffine coordinates as a Scalar.
    messages.push(*stealth_addr.0.x());
    messages.push(*stealth_addr.0.y());
    // Push both JubJubAffine coordinates as a Scalar.
    messages.push(*stealth_addr.1.x());
    messages.push(*stealth_addr.1.y());
    messages.push(hashed_secret);
    // Push both JubJubAffine coordinates as a Scalar.
    messages.push(*commitment.x());
    messages.push(*commitment.y());
    // Add elebility & expiration timestamps.
    messages.push(eligibility);
    messages.push(expiration);
    // Add position of the bid in the BidTree
    messages.push(pos);

    // Perform the sponge_hash inside of the Constraint System
    sponge::gadget(composer, &messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_pki::{PublicSpendKey, SecretSpendKey};
    use dusk_plonk::jubjub::GENERATOR_EXTENDED;
    use plonk_gadgets::AllocatedScalar;
    use rand::Rng;

    fn random_bid(secret: &JubJubScalar) -> Bid {
        let mut rng = rand::thread_rng();

        let secret_k = BlsScalar::from(*secret);
        let pk_r = PublicSpendKey::from(SecretSpendKey::random(&mut rng));
        let stealth_addr = pk_r.gen_stealth_address(&secret);
        let secret = GENERATOR_EXTENDED * secret;
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN..crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);

        let eligibility = u64::MAX;
        let expiration = u64::MAX;

        Bid::new(
            &mut rng,
            &stealth_addr,
            &value,
            &secret.into(),
            secret_k,
            eligibility,
            expiration,
        )
        .expect("Bid creation error")
    }

    #[ignore]
    #[test]
    fn test_word_padding() {
        // This cannot be tested until we don't get propper test vectors from
        // the research side.
    }

    #[cfg(feature = "canon")]
    #[test]
    fn bid_preimage_gadget() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 14, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 13)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret);

        let circuit = |composer: &mut StandardComposer, bid: &Bid| {
            // Allocate Bid-internal fields
            let bid_hashed_secret =
                AllocatedScalar::allocate(composer, bid.hashed_secret);
            let bid_cipher = (
                composer.add_input(bid.encrypted_data.cipher()[0]),
                composer.add_input(bid.encrypted_data.cipher()[1]),
            );
            let bid_commitment = composer.add_affine(bid.c);
            let bid_stealth_addr = (
                composer.add_affine(bid.stealth_address.pk_r().as_ref().into()),
                composer.add_affine(bid.stealth_address.R().into()),
            );
            let eligibility = AllocatedScalar::allocate(
                composer,
                BlsScalar::from(bid.eligibility),
            );
            let expiration = AllocatedScalar::allocate(
                composer,
                BlsScalar::from(bid.expiration),
            );
            let pos =
                AllocatedScalar::allocate(composer, BlsScalar::from(bid.pos));
            let bid_hash = preimage_gadget(
                composer,
                bid_cipher,
                bid_commitment,
                bid_stealth_addr,
                bid_hashed_secret.var,
                eligibility.var,
                expiration.var,
                pos.var,
            );

            // Constraint the hash to be equal to the real one
            let storage_bid = bid.hash();
            composer.constrain_to_constant(
                bid_hash,
                BlsScalar::zero(),
                Some(-storage_bid),
            );
        };
        // Proving
        let mut prover = Prover::new(b"testing");
        circuit(prover.mut_cs(), &bid);
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        circuit(verifier.mut_cs(), &bid);
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().construct_dense_pi_vec();
        verifier.verify(&proof, &vk, &pi)
    }
}
