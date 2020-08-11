//! Encoding module for Bid structure.
//!
//! See: https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L

use super::Bid;
use dusk_plonk::jubjub::AffinePoint;
use dusk_plonk::prelude::*;
use poseidon252::{sponge::sponge::*, StorageScalar};

#[derive(Copy, Clone, Debug, Default)]
pub struct StorageBid {
    // t_a
    pub(crate) elegibility_ts: u32,
    // t_e
    pub(crate) expiration_ts: u32,
    // b_enc (encrypted blinder)
    pub(crate) encrypted_blinder: (AffinePoint, AffinePoint),
    // v_enc (encrypted_value)
    pub(crate) encrypted_value: (AffinePoint, AffinePoint),
    // R = r * G
    pub(crate) randomness: AffinePoint,
    // m
    pub(crate) hashed_secret: BlsScalar,
    // pk (Public Key - Stealth Address)
    pub(crate) pk: AffinePoint,
    // c (Pedersen Commitment)
    pub(crate) c: AffinePoint,
}

/// Encodes a `Bid` in a `StorageScalar` form by applying the correct encoding
/// methods
impl From<&Bid> for StorageBid {
    fn from(bid: &Bid) -> StorageBid {
        StorageBid {
            elegibility_ts: bid.elegibility_ts,
            expiration_ts: bid.expiration_ts,
            encrypted_blinder: bid.encrypted_blinder,
            encrypted_value: bid.encrypted_value,
            randomness: bid.randomness,
            hashed_secret: bid.hashed_secret,
            pk: bid.pk,
            c: bid.c,
        }
    }
}

/// Encodes a `StorageBid` in a `StorageScalar` form by applying the correct
/// encoding methods and collapsing it into a `StorageScalar` which can be then
/// stored inside of a `kelvin` tree data structure.
impl Into<StorageScalar> for StorageBid {
    fn into(self) -> StorageScalar {
        // Generate an empty vector of `Scalar` which will store the
        // representation of all of the `Bid` elements.
        let mut words_deposit = Vec::new();
        // Note that the merkle_tree_root is not used since we can't pre-compute
        // it. Therefore, any field that relies on it to be computed isn't
        // neither used to obtain this encoded form.

        // 1. Generate the type_fields Scalar Id:
        // Type 1 will be BlsScalar
        // Type 2 will be JubJubScalar
        // Type 3 will be JubJubAffine
        // Type 4 will be u32
        // Byte-types are treated in Little Endian.

        // Safe unwrap here.
        let type_fields =
            BlsScalar::from_bytes(b"44333313300000000000000000000000").unwrap();
        words_deposit.push(type_fields);

        // 2. Encode each word.
        // Scalar and any other type that can be embedded in, will also be
        // treated as one.
        words_deposit.push(BlsScalar::from(self.elegibility_ts as u64));
        words_deposit.push(BlsScalar::from(self.expiration_ts as u64));

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.encrypted_value.0.get_x());
        words_deposit.push(self.encrypted_value.0.get_y());
        words_deposit.push(self.encrypted_blinder.1.get_x());
        words_deposit.push(self.encrypted_blinder.1.get_y());

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.pk.get_x());
        words_deposit.push(self.pk.get_y());

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.randomness.get_x());
        words_deposit.push(self.randomness.get_y());

        words_deposit.push(self.hashed_secret);

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(self.c.get_x());
        words_deposit.push(self.c.get_y());

        // Once all of the words are translated as `Scalar` and stored
        // correctly, apply the Poseidon sponge hash function to obtain
        // the encoded form of the `Bid`.
        StorageScalar(sponge_hash(&words_deposit))
    }
}

impl StorageBid {
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
        let type_fields =
            BlsScalar::from_bytes(b"44333313300000000000000000000000").unwrap();
        // Add to the composer the values required for the preimage.
        let mut messages: Vec<Variable> = vec![];
        messages.push(composer.add_input(type_fields));
        messages.push(
            composer.add_input(BlsScalar::from(self.elegibility_ts as u64)),
        );
        messages.push(
            composer.add_input(BlsScalar::from(self.expiration_ts as u64)),
        );
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.encrypted_value.0.get_x()));
        messages.push(composer.add_input(self.encrypted_value.0.get_y()));
        messages.push(composer.add_input(self.encrypted_blinder.1.get_x()));
        messages.push(composer.add_input(self.encrypted_blinder.1.get_y()));
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.pk.get_x()));
        messages.push(composer.add_input(self.pk.get_y()));
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.randomness.get_x()));
        messages.push(composer.add_input(self.randomness.get_y()));
        messages.push(composer.add_input(self.hashed_secret));
        // Push both JubJubAffine coordinates as a Scalar.
        messages.push(composer.add_input(self.c.get_x()));
        messages.push(composer.add_input(self.c.get_y()));

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
    use crate::score_gen::Score;
    use dusk_plonk::jubjub::{GENERATOR, GENERATOR_NUMS};
    use failure::Error;
    use rand_core::RngCore;

    pub(self) fn gen_val_blinder_and_commitment(
    ) -> (JubJubScalar, JubJubScalar, AffinePoint) {
        let value = JubJubScalar::from(235_000u64);
        let blinder = JubJubScalar::random(&mut rand::thread_rng());

        let commitment: AffinePoint = AffinePoint::from(
            &(GENERATOR.to_niels() * value)
                + &(GENERATOR_NUMS.to_niels() * blinder),
        );
        (value, blinder, commitment)
    }

    #[ignore]
    #[test]
    fn test_word_padding() {
        // This cannot be tested until we don't get propper test vectors from
        // the research side.
    }

    #[test]
    fn storage_bid_preimage_gadget() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        let (value, _, commitment) = gen_val_blinder_and_commitment();

        // Generate a correct Bid
        let storage_bid =
            StorageBid::from(
                &Bid {
                    bid_tree_root: BlsScalar::random(&mut rand::thread_rng()),
                    consensus_round_seed: BlsScalar::random(
                        &mut rand::thread_rng(),
                    ),
                    latest_consensus_round: BlsScalar::random(
                        &mut rand::thread_rng(),
                    ),
                    latest_consensus_step: BlsScalar::random(
                        &mut rand::thread_rng(),
                    ),
                    elegibility_ts: rand::thread_rng().next_u32(),
                    expiration_ts: rand::thread_rng().next_u32(),
                    prover_id: BlsScalar::default(),
                    score: Score::default(),

                    encrypted_blinder: (
                        AffinePoint::default(),
                        AffinePoint::default(),
                    ),
                    encrypted_value: (
                        AffinePoint::default(),
                        AffinePoint::default(),
                    ),
                    randomness: AffinePoint::identity(),
                    secret_k: BlsScalar::random(&mut rand::thread_rng()),
                    hashed_secret: BlsScalar::default(),
                    pk: AffinePoint::identity(),
                    c: commitment,
                }
                .init(&value)?,
            );

        // Proving
        let mut prover = Prover::new(b"testing");
        storage_bid.preimage_gadget(prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        storage_bid.preimage_gadget(verifier.mut_cs());
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        verifier.verify(&proof, &vk, &pi)
    }
}
