//! Score generation

use super::errors::ScoreError;
use crate::bid::Bid;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use failure::Error;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use poseidon252::sponge::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Score {
    pub(crate) score: Scalar,
    pub(crate) r1: Scalar,
    pub(crate) r2: Scalar,
}

impl Score {
    pub(crate) fn new(score: Scalar, r1: Scalar, r2: Scalar) -> Self {
        Score { score, r1, r2 }
    }
}

pub fn compute_score(bid: &Bid) -> Result<Score, Error> {
    // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed, latest_consensus_round, latest_consensus_step)`.
    let y = sponge::sponge_hash(&[
        bid.secret_k,
        bid.bid_tree_root,
        bid.consensus_round_seed,
        bid.latest_consensus_round,
        bid.latest_consensus_step,
    ]);

    // Truncate Y to left 128 bits and interpret the result as 128-bit integer.
    // Keep the right 128 bits as another integer (r1).
    let y_prime = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
    let r1 = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

    // Get the bid value outside of the modular field and treat it as
    // an integer.
    let bid_value = BigUint::from_bytes_le(&bid.value.to_bytes());
    // Compute the final score
    let (f, r2) = match y_prime == BigUint::zero() {
        // If y' != 0 -> f = (bid_value * 2^128 / y')
        // r2 is assigned to the remainder of the division.
        false => {
            let num = bid_value * (BigUint::one() << 128);
            (num.clone() / y_prime.clone(), num % y_prime)
        }
        // If y' == 0 -> f = bid_value * 2^128
        // Since there's not any division, r2 is assigned to 0 since
        // there's not any remainder.
        true => (bid_value * (BigUint::one() << 128), BigUint::zero()),
    };

    // Get Scalars from the bigUints and return a `Score` if the conversions could
    // be correctly done.
    Ok(Score::new(
        biguint_to_scalar(f)?,
        biguint_to_scalar(r1)?,
        biguint_to_scalar(r2)?,
    ))
}

/// Computes the score of the bid printing in the ConstraintSystem the proof of the correct
/// obtention of the score.
///
/// Takes 3615 constraints.
pub fn compute_score_gadget(
    composer: &mut StandardComposer,
    bid: &Bid,
    bid_value: Variable,
    secret_k: Variable,
    bid_tree_root: Variable,
    consensus_round_seed: Variable,
    latest_consensus_round: Variable,
    latest_consensus_step: Variable,
) -> Variable {
    unimplemented!()
}

// Given the y parameter, return the y' and it's inverse value.
fn biguint_to_scalar(biguint: BigUint) -> Result<Scalar, Error> {
    let mut bytes = [0u8; 32];
    let biguint_bytes = biguint.to_bytes_le();
    if biguint_bytes.len() >= 32 {
        return Err(ScoreError::InvalidScoreFieldsLen.into());
    };
    bytes[0..biguint_bytes.len()].copy_from_slice(&biguint_bytes[..]);
    // Due to the previous conditions, we can unwrap here safely.
    Ok(Scalar::from_bytes(&bytes).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_bls12_381::G1Affine;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::constraint_system::{StandardComposer, Variable};
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;
}
