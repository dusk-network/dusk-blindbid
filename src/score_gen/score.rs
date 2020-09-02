// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Score generation

use super::errors::ScoreError;
use super::{MINUS_ONE_MOD_2_POW_128, SCALAR_FIELD_ORD_DIV_2_POW_128};
use crate::bid::Bid;
use anyhow::{Error, Result};
use dusk_plonk::jubjub::AffinePoint;
use dusk_plonk::prelude::*;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use plonk_gadgets::{
    AllocatedScalar, RangeGadgets::max_bound, ScalarGadgets::maybe_equal,
};
use poseidon252::sponge::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Score {
    pub(crate) score: BlsScalar,
    pub(crate) y: BlsScalar,
    pub(crate) y_prime: BlsScalar,
    pub(crate) r1: BlsScalar,
    pub(crate) r2: BlsScalar,
}

impl Score {
    pub(crate) fn new(
        score: BlsScalar,
        y: BlsScalar,
        y_prime: BlsScalar,
        r1: BlsScalar,
        r2: BlsScalar,
    ) -> Self {
        Score {
            score,
            y,
            y_prime,
            r1,
            r2,
        }
    }
}

impl Bid {
    /// Given a `Bid`, compute it's Score and return it.
    pub fn compute_score(
        &self,
        secret: &AffinePoint,
        secret_k: BlsScalar,
        bid_tree_root: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: BlsScalar,
        latest_consensus_step: BlsScalar,
    ) -> Result<Score, Error> {
        // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed,
        // latest_consensus_round, latest_consensus_step)`.
        let y = sponge::sponge_hash(&[
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ]);
        let (value, _) = self.decrypt_data(secret)?;

        // Truncate Y to left 128 bits and interpret the result as 128-bit integer.
        // Keep the right 128 bits as another integer (r1).
        let r1 = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
        let y_prime = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

        // Get the bid value outside of the modular field and treat it as
        // an integer.
        let bid_value = BigUint::from_bytes_le(&value.to_bytes());
        // Compute the final score
        let (f, r2) = match y_prime == BigUint::zero() {
            // If y' != 0 -> f = (bid_value * 2^128 / y')
            // r2 is assigned to the remainder of the division.
            false => {
                let num = bid_value * (BigUint::one() << 128);
                (&num / &y_prime, &num % &y_prime)
            }
            // If y' == 0 -> f = bid_value * 2^128
            // Since there's not any division, r2 is assigned to 0 since
            // there's not any remainder.
            true => (bid_value * (BigUint::one() << 128), BigUint::zero()),
        };

        // Get Scalars from the bigUints and return a `Score` if the conversions
        // could be correctly done.
        Ok(Score::new(
            biguint_to_scalar(f)?,
            y,
            biguint_to_scalar(y_prime)?,
            biguint_to_scalar(r1)?,
            biguint_to_scalar(r2)?,
        ))
    }
}

/// Proves that a `Score` is correctly generated.
/// Prints the proving statements in the passed Constraint System.
pub fn prove_correct_score_gadget(
    composer: &mut StandardComposer,
    bid: Bid,
    score: Score,
    bid_value: AllocatedScalar,
    secret_k: AllocatedScalar,
    bid_tree_root: AllocatedScalar,
    consensus_round_seed: AllocatedScalar,
    latest_consensus_round: AllocatedScalar,
    latest_consensus_step: AllocatedScalar,
) -> Result<(), Error> {
    // Allocate constant one & zero values.
    let one = composer.add_witness_to_circuit_description(BlsScalar::one());
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    // Allocate Score fields needed for the gadget.
    let r1 = AllocatedScalar::allocate(composer, score.r1);
    let r2 = AllocatedScalar::allocate(composer, score.r2);
    let y = AllocatedScalar::allocate(composer, score.y);
    let y_prime = AllocatedScalar::allocate(composer, score.y_prime);
    let score_alloc_scalar = AllocatedScalar::allocate(composer, score.score);
    let two_pow_128 = BlsScalar::from(2u64).pow(&[128, 0, 0, 0]);

    // 1. y = H(k||H(Bi)||sigma^s||k^t||k^s)
    let should_be_y = sponge::sponge_hash_gadget(
        composer,
        &[
            secret_k.var,
            bid_tree_root.var,
            consensus_round_seed.var,
            latest_consensus_round.var,
            latest_consensus_step.var,
        ],
    );
    // Constrain the result of the hash to be equal to the Score y
    composer.assert_equal(should_be_y, y.var);

    // 2. Y = 2^128 * r1 + Y'
    composer.add_gate(
        y_prime.var,
        r1.var,
        y.var,
        BlsScalar::one(),
        two_pow_128,
        -BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // 3.(r1 < |Fr|/2^128 AND Y' < 2^128) OR (r1 = |Fr|/2^128 AND Y' < |Fr| mod
    // 2^128).
    //
    // 3.1. First op will be a complex rangeproof between r1 and the range
    // (Order of the Scalar Field / 2^128 (No modular division)) The result
    // should be 0 if the rangeproof holds.
    let first_cond = max_bound(composer, SCALAR_FIELD_ORD_DIV_2_POW_128, r1).0;

    // 3.2. Then we have a single Rangeproof between Y' being in the range
    // [0-2^128]
    let second_cond = max_bound(composer, two_pow_128, y_prime).0;
    // 3.3. Third, we have an equalty checking between r1 & the order of the
    // Scalar field divided (no modular division) by 2^128.
    // Since the gadget uses an `AllocatedScalar` here, we need to previously
    // constrain it's variable to a constant value: `the order of the
    // Scalar field divided (no modular division) by 2^128` in this case. Then generate
    // the `AllocatedScalar` and call the gadget.
    let scalar_field_ord_div_2_128_variable = composer
        .add_witness_to_circuit_description(SCALAR_FIELD_ORD_DIV_2_POW_128);
    let scalar_field_ord_div_2_128 = AllocatedScalar {
        var: scalar_field_ord_div_2_128_variable,
        scalar: SCALAR_FIELD_ORD_DIV_2_POW_128,
    };
    // Now we can call the gadget with all the constraints applied to ensure that the variable
    // that represents 2^128
    let third_cond = maybe_equal(composer, scalar_field_ord_div_2_128, r1);
    // 3.4. Finally, constraints for y' checking it's between
    // [0, Order of the ScalarField mod 2^128].
    let fourth_cond = max_bound(composer, MINUS_ONE_MOD_2_POW_128, y_prime).0;
    // Apply the point 3 constraint.
    //(r1 < |Fr|/2^128 AND Y' < 2^128 +1)
    let left_assign = composer.mul(
        BlsScalar::one(),
        first_cond,
        second_cond,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // (r1 = |Fr|/2^128 AND Y' < |Fr| mod 2^128)
    let right_assign = composer.mul(
        BlsScalar::one(),
        third_cond,
        fourth_cond,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // left_assign XOR right_assign = 1
    // This is possible since condition 1. and 3. are mutually exclusive. That
    // means that if one is true, the other part of the equation will be
    // false (0). Therefore, we can apply a mul gate since the inputs are
    // boolean and both sides of the equal can't be true, but both can be
    // false, and this has to make the proof fail. The following gate
    // computes the XOR and constraints the result to be equal to one.
    composer.add_gate(
        left_assign,
        right_assign,
        one,
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        -BlsScalar::one(),
        BlsScalar::zero(),
    );

    // 4. r2 < Y' we need a 128-bit range_proof
    let should_be_1 = max_bound(composer, y_prime.scalar, score_alloc_scalar).0;
    // Check that the result of the range_proof is indeed 0 to assert it passed.
    composer.constrain_to_constant(
        should_be_1,
        BlsScalar::one(),
        BlsScalar::zero(),
    );

    // 5. q < 2^120
    composer.range_gate(score_alloc_scalar.var, 120usize);
    // 5. q*Y' + r2 -d*2^128 = 0
    //
    // f * Y'
    let f_y_prime_prod = composer.mul(
        BlsScalar::one(),
        score_alloc_scalar.var,
        y_prime.var,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // q*Y' + r2
    let left = composer.add(
        (BlsScalar::one(), f_y_prime_prod),
        (BlsScalar::one(), r2.var),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // (q*Y' + r2) - v*2^128 = 0
    composer.add_gate(
        left,
        bid_value.var,
        zero,
        BlsScalar::one(),
        -two_pow_128,
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    Ok(())
}

// Given the y parameter, return the y' and it's inverse value.
fn biguint_to_scalar(biguint: BigUint) -> Result<BlsScalar, Error> {
    let mut bytes = [0u8; 32];
    let biguint_bytes = biguint.to_bytes_le();
    if biguint_bytes.len() > 32 {
        return Err(ScoreError::InvalidScoreFieldsLen.into());
    };
    bytes[..biguint_bytes.len()].copy_from_slice(&biguint_bytes[..]);
    // Due to the previous conditions, we can unwrap here safely.
    Ok(BlsScalar::from_bytes(&bytes).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_plonk::jubjub::GENERATOR_EXTENDED;
    use rand::Rng;

    fn random_bid(secret: &JubJubScalar) -> Result<Bid, Error> {
        let mut rng = rand::thread_rng();

        let secret_k = BlsScalar::random(&mut rng);
        let secret = GENERATOR_EXTENDED * secret;
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);

        Bid::init(
            AffinePoint::from(secret),
            &mut rng,
            &value,
            &AffinePoint::from(secret),
            secret_k,
        )
    }

    #[test]
    fn biguint_scalar_conversion() {
        let rand_scalar = BlsScalar::random(&mut rand::thread_rng());
        let big_uint = BigUint::from_bytes_le(&rand_scalar.to_bytes());

        assert_eq!(biguint_to_scalar(big_uint).unwrap(), rand_scalar)
    }

    fn allocate_fields(
        composer: &mut StandardComposer,
        value: JubJubScalar,
        secret_k: BlsScalar,
        bid_tree_root: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: BlsScalar,
        latest_consensus_step: BlsScalar,
    ) -> (
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
    ) {
        let value = AllocatedScalar::allocate(composer, value.into());

        let secret_k = AllocatedScalar::allocate(composer, secret_k);
        let bid_tree_root = AllocatedScalar::allocate(composer, bid_tree_root);
        let consensus_round_seed =
            AllocatedScalar::allocate(composer, consensus_round_seed);
        let latest_consensus_round =
            AllocatedScalar::allocate(composer, latest_consensus_round);
        let latest_consensus_step =
            AllocatedScalar::allocate(composer, latest_consensus_step);
        (
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )
    }

    #[test]
    fn correct_score_gen_proof() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let mut bid = random_bid(&secret)?;
        let secret = GENERATOR_EXTENDED * &secret;
        let (value, _) = bid.decrypt_data(&secret.into())?;

        // Generate fields for the Bid & required by the compute_score
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_step = BlsScalar::random(&mut rand::thread_rng());

        // Edit score fields which should make the test fail
        let mut score = bid.compute_score(
            &secret.into(),
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Proving
        let mut prover = Prover::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            prover.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        );
        prove_correct_score_gadget(
            prover.mut_cs(),
            bid,
            score,
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        )?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            verifier.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        );
        prove_correct_score_gadget(
            verifier.mut_cs(),
            bid,
            score,
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }

    #[test]
    fn incorrect_score_gen_proof() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let mut bid = random_bid(&secret)?;
        let secret = GENERATOR_EXTENDED * &secret;
        let (value, _) = bid.decrypt_data(&secret.into())?;

        // Generate fields for the Bid & required by the compute_score
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_step = BlsScalar::random(&mut rand::thread_rng());

        // Edit score fields which should make the test fail
        let mut score = bid.compute_score(
            &secret.into(),
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;
        score.score = BlsScalar::from(5686536568u64);
        score.r1 = BlsScalar::from(5898956968u64);

        // Proving
        let mut prover = Prover::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            prover.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        );
        prove_correct_score_gadget(
            prover.mut_cs(),
            bid,
            score,
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        )?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            verifier.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        );
        prove_correct_score_gadget(
            verifier.mut_cs(),
            bid,
            score,
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        verifier.preprocess(&ck)?;
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_err());

        Ok(())
    }
}
