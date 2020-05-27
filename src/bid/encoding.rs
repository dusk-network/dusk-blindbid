//! Encoding module for Bid structure.
//!
//! See: https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L

use super::errors::BidError;
use super::Bid;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use failure::Error;
use poseidon252::{sponge::sponge::*, StorageScalar};

/// Encodes a `Bid` in a `StorageScalar` form by applying the correct encoding methods
/// and collapsing it into a `StorageScalar` which can be then stored inside of a
/// `kelvin` tree data structure.
pub(crate) fn tree_leaf_encoding(bid: &Bid) -> Result<StorageScalar, Error> {
    // Generate an empty vector of `Scalar` which will store the representation
    // of all of the `Bid` elements that a.
    let mut words_deposit = Vec::new();
    // Note that the merkle_tree_root is not used since we can't pre-compute
    // it. Therefore, any field that relies on it to be computed isn't neither
    // used to obtain this encoded form.

    // 1. Generate the type_fields Scalar Id:
    // Type 1 will be BlsScalar
    // Type 2 will be JubJubScalar
    // Type 3 will be JubJubAffine
    // Treated in Little Endian.
    let type_fields = Scalar::from_bytes(b"11111122130000000000000000000000");

    // 2. Encode each word.
    // Scalar and any other type that can be embedded in, will also be treated as one.
    words_deposit.push(bid.consensus_round_seed);
    words_deposit.push(bid.latest_consensus_round);
    words_deposit.push(bid.latest_consensus_step);
    if bid.prover_id == None {
        return Err(BidError::MissingBidFields.into());
    };
    words_deposit.push(bid.prover_id.unwrap());
    if bid.score == None {
        return Err(BidError::MissingBidFields.into());
    }
    words_deposit.push(bid.score.unwrap().score);
    // Wrap up JubJubScalar bytes into BlsScalar bytes for value and randomness terms
    words_deposit.push(Scalar::from_bytes(&bid.value.to_bytes()).unwrap());
    words_deposit.push(Scalar::from_bytes(&bid.randomness.to_bytes()).unwrap());
    words_deposit.push(bid.secret_k);
    // Push both JubJubAffine coordinates as a Scalar.
    words_deposit.push(Scalar::from_bytes(&bid.pk.get_x().to_bytes()).unwrap());
    words_deposit.push(Scalar::from_bytes(&bid.pk.get_y().to_bytes()).unwrap());

    // Once all of the words are translated as `Scalar` and stored correctly,
    // apply the Poseidon sponge hash function to obtain the encoded form of the
    // `Bid`.
    Ok(StorageScalar(sponge_hash(&words_deposit)))
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
