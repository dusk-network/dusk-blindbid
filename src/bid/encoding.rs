//! Encoding module for Bid structure.
//!
//! See: https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L

use super::errors::BidError;
use super::Bid;
use dusk_bls12_381::Scalar;
use failure::Error;
use poseidon252::{sponge::sponge::*, StorageScalar};

const BYTE_PADDING_LEN: usize = 28;

/// Encodes a `Bid` in a `StorageScalar` form by applying the correct padding
/// and encoding methods stated in https://hackmd.io/@7dpNYqjKQGeYC7wMlPxHtQ/BkfS78Y9L
/// and collapsing it into a `StorageScalar` which can be then stored inside of a
/// `kelvin` tree data structure.
pub(crate) fn tree_leaf_encoding(bid: &Bid) -> Result<StorageScalar, Error> {
    // Generate an empty vector of bytes which will store the padded & encoded
    // byte-representation of all of the `Bid` elements.
    let mut byte_container = Vec::with_capacity(28 * 9);
    // Note that the merkle_tree_root is not used since we can't pre-compute
    // it. Therefore, any field that relies on it to be computed isn't neither
    // used to obtain this encoded form.
    pad_and_accumulate(&mut byte_container, &bid.consensus_round_seed.to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.latest_consensus_round.to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.latest_consensus_step.to_bytes());
    if bid.prover_id == None {
        return Err(BidError::MissingBidFields.into());
    };
    pad_and_accumulate(&mut byte_container, &bid.prover_id.unwrap().to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.value.to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.randomness.to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.secret_k.to_bytes());
    pad_and_accumulate(&mut byte_container, &bid.pk.to_bytes());

    // Now that we have all of our values encoded inside the container,
    // collapse it and return the result.
    collapse_accumulator(&byte_container)
}

/// Applies the correct padding to whatever data structure that can be represented
/// as bytes.
fn pad_and_accumulate(byte_storage: &mut Vec<u8>, elem_as_bytes: &[u8]) {
    // Push the bytes of the element into the byte_storage.
    byte_storage.extend(elem_as_bytes.iter());
    // Pad the element with `0x7`.
    byte_storage.push(7u8);
    // Pad with 0's until we reach a multiple of BYTE_PADDING_LEN as the total len of the byte storage.
    if byte_storage.len() % BYTE_PADDING_LEN != 0 {
        // Compute how much 0's we need to add as padding. And then, padd with 0's.
        byte_storage
            .extend(vec![0u8; BYTE_PADDING_LEN - byte_storage.len() % BYTE_PADDING_LEN].iter());
    }
}

/// Collapses a collection of previously-padded bytes into a single `StorageScalar`
/// using the Poseidon Sponge Hash function.
fn collapse_accumulator(byte_storage: &[u8]) -> Result<StorageScalar, Error> {
    // If the len is not multiple of BYTE_PADDING_LEN, return an error.
    if byte_storage.len() % BYTE_PADDING_LEN != 0 {
        return Err(BidError::WrongPadding.into());
    };
    // Generate a `Scalar` Vec where each `Scalar` is built from a chunk of 28 bytes
    // of the original `byte_storage`.
    let mut scalar_words = vec![];
    for chunk in byte_storage.chunks(BYTE_PADDING_LEN) {
        // Generate a 32-byte empty chunk
        let mut inserted_chunk = [0u8; 32];
        // Pad the 4-first bits as zero since `Scalar::from_bytes()` expects
        // a `&[u8; 32]`.
        inserted_chunk[4..32].copy_from_slice(chunk);
        // Push the Scalar word to the `scalar_words` vec.
        scalar_words.push(Scalar::from_bytes(&inserted_chunk).unwrap());
    }
    // Apply the sponge hash function to collapse all chunks into a single
    // `Scalar`.
    Ok(StorageScalar(sponge_hash(&scalar_words)))
}
