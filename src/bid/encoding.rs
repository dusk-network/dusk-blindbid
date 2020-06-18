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
impl Into<StorageScalar> for &StorageBid {
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use dusk_bls12_381::G1Affine;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use jubjub::{AffinePoint, Scalar as JubJubScalar};
    use merlin::Transcript;

    #[ignore]
    #[test]
    fn test_word_padding() {
        // This cannot be tested until we don't get propper test vectors from the research side.
    }
}
