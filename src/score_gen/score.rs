//! Score generation

use super::errors::ScoreError;
use crate::bid::Bid;
use anyhow::{Error, Result};
use dusk_plonk::prelude::*;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use plonk_gadgets::RangeGadgets::{max_bound, range_check};
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

/// Given a `Bid`, compute it's Score and return it.
pub(crate) fn compute_score(
    bid: &Bid,
    bid_value: &JubJubScalar,
) -> Result<Score, Error> {
    // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed,
    // latest_consensus_round, latest_consensus_step)`.
    let y = sponge::sponge_hash(&[
        bid.secret_k,
        bid.bid_tree_root,
        bid.consensus_round_seed,
        bid.latest_consensus_round,
        bid.latest_consensus_step,
    ]);

    // Truncate Y to left 128 bits and interpret the result as 128-bit integer.
    // Keep the right 128 bits as another integer (r1).
    let r1 = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
    let y_prime = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

    // Get the bid value outside of the modular field and treat it as
    // an integer.
    let bid_value = BigUint::from_bytes_le(&bid_value.to_bytes());
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

/// Proves that a `Score` is correctly generated.
/// Prints the proving statements in the passed Constraint System.
pub fn prove_correct_score_gadget(
    composer: &mut StandardComposer,
    bid: &Bid,
    bid_value: Variable,
) -> Result<(), Error> {
    let score = bid.score;
    let r1 = composer.add_input(score.r1);
    let r2 = composer.add_input(score.r2);
    let y = composer.add_input(score.y);
    let y_prime = composer.add_input(score.y_prime);
    let score_var = composer.add_input(score.score);
    let two_pow_128 = BlsScalar::from(2u64).pow(&[128, 0, 0, 0]);
    let two_pow_128_buint = BigUint::from_bytes_le(&two_pow_128.to_bytes());
    // 1. Y = 2^128 * r1 + Y'
    composer.add_gate(
        y_prime,
        r1,
        y,
        BlsScalar::one(),
        two_pow_128,
        -BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // 2.(r1 < |Fr|/2^128 AND Y' < 2^128) OR (r1 = |Fr|/2^128 AND Y' < |Fr| mod
    // 2^128).
    //
    // 2.1. First op will be a complex rangeproof between r1 and the range
    // (Order of the Scalar Field / 2^128 (No modular division)) The result
    // should be 0 if the rangeproof holds.
    let scalar_field_ord_div_2_pow_128 = {
        let scalar_field_order =
            BigUint::from_bytes_le(&(-BlsScalar::one()).to_bytes())
                + BigUint::one();
        scalar_field_order / &two_pow_128_buint
    };
    let first_cond = single_complex_range_proof(
        composer,
        score.r1,
        biguint_to_scalar(scalar_field_ord_div_2_pow_128.clone())?,
    )?;

    // 2.2. Then we have a single Rangeproof between Y' being in the range
    // [0-2^128]
    let second_cond =
        single_complex_range_proof(composer, score.y_prime, two_pow_128)?;
    // 2.3. Third, we have an equalty checking between r1 & the order of the
    // Scalar field divided (no modular division) by 2^128.
    // We simply subtract both values and if it's equal, we will get a 0.

    // Generate fixed&constrained value witnesses.
    let one = composer.add_input(BlsScalar::one());
    composer.constrain_to_constant(one, BlsScalar::one(), BlsScalar::zero());
    let zero = composer.add_input(BlsScalar::zero());
    composer.constrain_to_constant(zero, BlsScalar::zero(), BlsScalar::zero());

    let third_cond = {
        let zero_or_other = composer.add(
            (BlsScalar::one(), r1),
            (
                -biguint_to_scalar(scalar_field_ord_div_2_pow_128.clone())?,
                one,
            ),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let u = score.r1 - biguint_to_scalar(scalar_field_ord_div_2_pow_128)?;
        // Conditionally assign `1` or `0` to `y`.
        let y = if u == BlsScalar::zero() {
            composer.add_input(BlsScalar::one())
        } else {
            composer.add_input(BlsScalar::zero())
        };

        // Conditionally assign `1/u` or `0` to z
        let mut z = zero;
        if u != BlsScalar::zero() {
            // If u != zero -> `z = 1/u`
            // Otherways, `u = 0` as it was defined avobe.
            // Check inverse existance, otherways, err.
            if u.invert().is_none().into() {
                return Err(ScoreError::NonExistingInverse.into());
            };
            // Safe to unwrap here.
            z = composer.add_input(u.invert().unwrap());
        }
        // We can safely unwrap `u` now since we know that the inverse for `u`
        // exists. Now we need to check the following to ensure we can
        // provide a boolean result representing wether the rangeproof
        // holds or not: `u = Chi(x)`.
        // `u * z = 1 - y`.
        // `y * u = 0`.
        let one = composer.add_input(BlsScalar::one());
        composer.add_gate(
            one,
            zero_or_other,
            zero,
            u,
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let one_min_y = composer.add(
            (BlsScalar::one(), one),
            (-BlsScalar::one(), y),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let u_times_z =
            composer.mul(u, one, z, BlsScalar::zero(), BlsScalar::zero());
        composer.assert_equal(one_min_y, u_times_z);
        let y_times_u =
            composer.mul(u, one, y, BlsScalar::zero(), BlsScalar::zero());
        composer.assert_equal(y_times_u, zero);
        y
    };
    // 2.4. Finally, A rangeproof for y' checking it's between [0, Order of the
    // ScalarField mod 2^128]. We will apply the complex rangeproof too.
    let minus_one_mod_2_pow_128 = {
        let min_one = BigUint::from_bytes_le(&(-BlsScalar::one()).to_bytes());
        min_one % &two_pow_128_buint
    };
    let fourth_cond = single_complex_range_proof(
        composer,
        score.y_prime,
        biguint_to_scalar(minus_one_mod_2_pow_128)?,
    )?;
    // Apply the point 2 constraint.
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

    // 3. r2 < Y' we need a 128-bit range_proof
    let should_be_1 =
        single_complex_range_proof(composer, bid.score.r2, bid.score.y_prime)?;
    // Check that the result of the range_proof is indeed 0 to assert it passed.
    composer.constrain_to_constant(
        should_be_1,
        BlsScalar::one(),
        BlsScalar::zero(),
    );

    // 4. f < 2^120
    composer.range_gate(score_var, 120usize);
    // 5. f*Y' + r2 -d*2^128 = 0
    //
    // f * Y'
    let f_y_prime_prod = composer.mul(
        BlsScalar::one(),
        score_var,
        y_prime,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // f*Y' + r2
    let left = composer.add(
        (BlsScalar::one(), f_y_prime_prod),
        (BlsScalar::one(), r2),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // (f*Y' + r2) - d*2^128 = 0
    composer.add_gate(
        left,
        bid_value,
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
    use dusk_plonk::jubjub::{
        AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
    };
    use rand_core::RngCore;

    pub(self) fn gen_val_blinder_and_commitment(
    ) -> (JubJubScalar, JubJubScalar, AffinePoint) {
        let value = JubJubScalar::from(250_000u64);
        let blinder = JubJubScalar::random(&mut rand::thread_rng());

        let commitment: AffinePoint = AffinePoint::from(
            &(GENERATOR_EXTENDED * value)
                + &(GENERATOR_NUMS_EXTENDED * blinder),
        );
        (value, blinder, commitment)
    }

    #[test]
    fn biguint_scalar_conversion() {
        let rand_scalar = BlsScalar::random(&mut rand::thread_rng());
        let big_uint = BigUint::from_bytes_le(&rand_scalar.to_bytes());

        assert_eq!(biguint_to_scalar(big_uint).unwrap(), rand_scalar)
    }

    #[test]
    fn correct_score_gen_proof() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        let (value, _, commitment) = gen_val_blinder_and_commitment();

        // Generate a correct Bid
        let bid = &Bid {
            bid_tree_root: BlsScalar::random(&mut rand::thread_rng()),
            consensus_round_seed: BlsScalar::random(&mut rand::thread_rng()),
            latest_consensus_round: BlsScalar::random(&mut rand::thread_rng()),
            latest_consensus_step: BlsScalar::random(&mut rand::thread_rng()),
            elegibility_ts: rand::thread_rng().next_u32(),
            expiration_ts: rand::thread_rng().next_u32(),
            prover_id: BlsScalar::default(),
            score: Score::default(),
            encrypted_blinder: (AffinePoint::default(), AffinePoint::default()),
            encrypted_value: (AffinePoint::default(), AffinePoint::default()),
            randomness: AffinePoint::identity(),
            secret_k: BlsScalar::random(&mut rand::thread_rng()),
            hashed_secret: BlsScalar::default(),
            pk: AffinePoint::identity(),
            c: commitment,
        }
        .init(&value)?;

        // Proving
        let mut prover = Prover::new(b"testing");
        let value_var = prover.mut_cs().add_input(value.into());
        prove_correct_score_gadget(prover.mut_cs(), &bid, value_var)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        let value_var = verifier.mut_cs().add_input(value.into());
        prove_correct_score_gadget(verifier.mut_cs(), &bid, value_var)?;
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }

    #[test]
    fn incorrect_score_gen_proof() -> Result<(), Error> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        let (value, _, commitment) = gen_val_blinder_and_commitment();

        // Generate a correct Bid
        let mut bid = Bid {
            bid_tree_root: BlsScalar::random(&mut rand::thread_rng()),
            consensus_round_seed: BlsScalar::random(&mut rand::thread_rng()),
            latest_consensus_round: BlsScalar::random(&mut rand::thread_rng()),
            latest_consensus_step: BlsScalar::random(&mut rand::thread_rng()),
            elegibility_ts: rand::thread_rng().next_u32(),
            expiration_ts: rand::thread_rng().next_u32(),
            prover_id: BlsScalar::default(),
            score: Score::default(),
            encrypted_blinder: (AffinePoint::default(), AffinePoint::default()),
            encrypted_value: (AffinePoint::default(), AffinePoint::default()),
            randomness: AffinePoint::identity(),
            secret_k: BlsScalar::random(&mut rand::thread_rng()),
            hashed_secret: BlsScalar::default(),
            pk: AffinePoint::identity(),
            c: commitment,
        }
        .init(&value)?;

        // Edit score fields which should make the test fail
        let mut score = bid.score;
        score.score = BlsScalar::from(5686536568u64);
        score.r1 = BlsScalar::from(5898956968u64);
        bid.score = score;

        // Proving
        let mut prover = Prover::new(b"testing");
        let value_var = prover.mut_cs().add_input(value.into());
        prove_correct_score_gadget(prover.mut_cs(), &bid, value_var)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        let value_var = verifier.mut_cs().add_input(value.into());
        prove_correct_score_gadget(verifier.mut_cs(), &bid, value_var)?;
        verifier.preprocess(&ck)?;
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_err());

        Ok(())
    }
}
