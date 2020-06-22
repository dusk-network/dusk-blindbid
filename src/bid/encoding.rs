//! Encoding module for Bid structure.
//!
//! See: https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L

use super::Bid;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use jubjub::{AffinePoint as JubJubAffine, Scalar as JubJubScalar};
use poseidon252::{sponge::sponge::*, StorageScalar};

#[derive(Copy, Clone, Debug, Default)]
pub struct StorageBid {
    // t_a
    pub(crate) elegibility_ts: u32,
    // t_e
    pub(crate) expiration_ts: u32,
    // b_enc (encrypted blinder) // XXX: Scalar for now. Double check
    pub(crate) encrypted_blinder: JubJubScalar,
    // v_enc (encrypted_value)
    pub(crate) encrypted_value: JubJubScalar,
    // R = r * G
    pub(crate) randomness: JubJubAffine,
    // m
    pub(crate) hashed_secret: Scalar,
    // pk (Public Key - Stealth Address)
    pub(crate) pk: JubJubAffine,
    // c (Pedersen Commitment)
    pub(crate) c: JubJubAffine,
}

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

/// Encodes a `StorageBid` in a `StorageScalar` form by applying the correct encoding methods
/// and collapsing it into a `StorageScalar` which can be then stored inside of a
/// `kelvin` tree data structure.
impl Into<StorageScalar> for StorageBid {
    fn into(self) -> StorageScalar {
        // Generate an empty vector of `Scalar` which will store the representation
        // of all of the `Bid` elements.
        let mut words_deposit = Vec::new();
        // Note that the merkle_tree_root is not used since we can't pre-compute
        // it. Therefore, any field that relies on it to be computed isn't neither
        // used to obtain this encoded form.

        // 1. Generate the type_fields Scalar Id:
        // Type 1 will be BlsScalar
        // Type 2 will be JubJubScalar
        // Type 3 will be JubJubAffine
        // Type 4 will be u32
        // Byte-types are treated in Little Endian.

        // Safe unwrap here.
        let type_fields = Scalar::from_bytes(b"44223133000000000000000000000000").unwrap();
        words_deposit.push(type_fields);

        // 2. Encode each word.
        // Scalar and any other type that can be embedded in, will also be treated as one.
        words_deposit.push(Scalar::from(self.elegibility_ts as u64));
        words_deposit.push(Scalar::from(self.expiration_ts as u64));
        // Unwraping a conversion between JubJubScalar to BlsScalar is always safe since the order of
        // the JubJubScalar field is shorter than the BlsScalar one.
        words_deposit.push(Scalar::from_bytes(&self.encrypted_blinder.to_bytes()).unwrap());
        words_deposit.push(Scalar::from_bytes(&self.encrypted_value.to_bytes()).unwrap());
        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(Scalar::from_bytes(&self.randomness.get_x().to_bytes()).unwrap());
        words_deposit.push(Scalar::from_bytes(&self.randomness.get_y().to_bytes()).unwrap());

        words_deposit.push(self.hashed_secret);
        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(Scalar::from_bytes(&self.pk.get_x().to_bytes()).unwrap());
        words_deposit.push(Scalar::from_bytes(&self.pk.get_y().to_bytes()).unwrap());

        // Push both JubJubAffine coordinates as a Scalar.
        words_deposit.push(Scalar::from_bytes(&self.c.get_x().to_bytes()).unwrap());
        words_deposit.push(Scalar::from_bytes(&self.c.get_y().to_bytes()).unwrap());

        // Once all of the words are translated as `Scalar` and stored correctly,
        // apply the Poseidon sponge hash function to obtain the encoded form of the
        // `Bid`.
        StorageScalar(sponge_hash(&words_deposit))
    }
}

impl StorageBid {
    /// Applies a preimage_gadget to the `StorageBid` fields hashing them and constraining
    /// the result of the sponge hash to the real/expected `StorageBid` encoded value
    /// expressed as `Scalar/StorageScalar`.
    ///
    /// The expected encoded value is a Public Input for this circuit.
    /// Appart from that, the preimage_gadget hashing result is returned.
    pub(crate) fn preimage_gadget(&self, composer: &mut StandardComposer) -> Variable {
        // This field represents the types of the inputs and has to be the same as the
        // default one.
        let type_fields = Scalar::from_bytes(b"44223133000000000000000000000000").unwrap();
        // Add to the composer the values required for the preimage.
        let mut messages: Vec<Variable> = vec![];
        messages.push(composer.add_input(type_fields));
        messages.push(composer.add_input(Scalar::from(self.elegibility_ts as u64)));
        messages.push(composer.add_input(Scalar::from(self.expiration_ts as u64)));
        messages.push(
            composer.add_input(Scalar::from_bytes(&self.encrypted_blinder.to_bytes()).unwrap()),
        );
        messages.push(
            composer.add_input(Scalar::from_bytes(&self.encrypted_value.to_bytes()).unwrap()),
        );
        messages.push(
            composer.add_input(Scalar::from_bytes(&self.randomness.get_x().to_bytes()).unwrap()),
        );
        messages.push(
            composer.add_input(Scalar::from_bytes(&self.randomness.get_y().to_bytes()).unwrap()),
        );
        messages.push(composer.add_input(self.hashed_secret));
        messages.push(composer.add_input(Scalar::from_bytes(&self.pk.get_x().to_bytes()).unwrap()));
        messages.push(composer.add_input(Scalar::from_bytes(&self.pk.get_y().to_bytes()).unwrap()));
        messages.push(composer.add_input(Scalar::from_bytes(&self.c.get_x().to_bytes()).unwrap()));
        messages.push(composer.add_input(Scalar::from_bytes(&self.c.get_y().to_bytes()).unwrap()));

        // Perform the sponge_hash inside of the Constraint System
        let storage_bid_hash = sponge_hash_gadget(composer, &messages);
        // Constraint the hash to be equal to the real one
        let real_hash: StorageScalar = self.clone().into();
        let real_hash: Scalar = real_hash.into();
        composer.constrain_to_constant(storage_bid_hash, Scalar::zero(), -real_hash);
        storage_bid_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use jubjub::{AffinePoint, Scalar as JubJubScalar};
    use merlin::Transcript;
    use rand_core::RngCore;

    #[ignore]
    #[test]
    fn test_word_padding() {
        // This cannot be tested until we don't get propper test vectors from the research side.
    }

    #[test]
    fn storage_bid_preimage_gadget() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        // Generate a correct Bid
        let storage_bid = StorageBid::from(
            &Bid::new(
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
                rand::thread_rng().next_u32(),
                rand::thread_rng().next_u32(),
                JubJubScalar::from(99u64),
                JubJubScalar::from(199u64),
                JubJubScalar::from(6546546u64),
                JubJubScalar::from(655588855476u64),
                AffinePoint::identity(),
                Scalar::random(&mut rand::thread_rng()),
                Scalar::random(&mut rand::thread_rng()),
                AffinePoint::identity(),
                AffinePoint::identity(),
            )
            .unwrap(),
        );

        // Apply the preimage_gadget
        let _ = storage_bid.preimage_gadget(&mut composer);

        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();

        let prep_circ = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }
}
