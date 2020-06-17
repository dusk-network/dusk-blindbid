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
    pub(crate) y: Scalar,
    pub(crate) y_prime: Scalar,
    pub(crate) r1: Scalar,
    pub(crate) r2: Scalar,
}

impl Score {
    pub(crate) fn new(score: Scalar, y: Scalar, y_prime: Scalar, r1: Scalar, r2: Scalar) -> Self {
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
pub(crate) fn compute_score(bid: &Bid) -> Result<Score, Error> {
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
    let r1 = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
    let y_prime = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

    // Get the bid value outside of the modular field and treat it as
    // an integer.
    let bid_value = BigUint::from_bytes_le(&bid.value.to_bytes());
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

    // Get Scalars from the bigUints and return a `Score` if the conversions could
    // be correctly done.
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
pub fn prove_correct_score_gadget(composer: &mut StandardComposer, bid: &Bid) -> Result<(), Error> {
    // This unwrap is safe since the order of the JubJubScalar is shorter.
    let bid_value = composer.add_input(Scalar::from_bytes(&bid.value.to_bytes()).unwrap());
    // Safe to unwrap here.
    let score = bid.score;
    let r1 = composer.add_input(score.r1);
    let r2 = composer.add_input(score.r2);
    let y = composer.add_input(score.y);
    let y_prime = composer.add_input(score.y_prime);
    let score_var = composer.add_input(score.score);
    let two_pow_128 = Scalar::from(2u64).pow(&[128, 0, 0, 0]);
    let two_pow_128_buint = BigUint::from_bytes_le(&two_pow_128.to_bytes());
    // 1. Y = 2^128 * r1 + Y'
    composer.add_gate(
        y_prime,
        r1,
        y,
        Scalar::one(),
        two_pow_128,
        -Scalar::one(),
        Scalar::zero(),
        Scalar::zero(),
    );
    // 2.(r1 < |Fr|/2^128 AND Y' < 2^128) OR (r1 = |Fr|/2^128 AND Y' < |Fr| mod 2^128).
    //
    // 2.1. First op will be a complex rangeproof between r1 and the range (Order of the Scalar Field / 2^128 (No modular division))
    // The result should be 0 if the rangeproof holds.
    let scalar_field_ord_div_2_pow_128 = {
        let scalar_field_order =
            BigUint::from_bytes_le(&(-Scalar::one()).to_bytes()) + BigUint::one();
        scalar_field_order / &two_pow_128_buint
    };
    let first_cond = single_complex_range_proof(
        composer,
        score.r1,
        biguint_to_scalar(scalar_field_ord_div_2_pow_128.clone())?,
    )?;

    // 2.2. Then we have a single Rangeproof between Y' being in the range [0-2^128]
    let second_cond = single_complex_range_proof(composer, score.y_prime, two_pow_128)?;
    // 2.3. Third, we have an equalty checking between r1 & the order of the Scalar field divided (no modular division)
    // by 2^128.
    // We simply subtract both values and if it's equal, we will get a 0.

    let one = composer.add_input(Scalar::one());
    let third_cond = {
        let zero_or_other = composer.add(
            (Scalar::one(), r1),
            (
                -biguint_to_scalar(scalar_field_ord_div_2_pow_128.clone())?,
                one,
            ),
            Scalar::zero(),
            Scalar::zero(),
        );
        let u = score.r1 - biguint_to_scalar(scalar_field_ord_div_2_pow_128)?;
        // Conditionally assign `1` or `0` to `y`.
        let y = if u == Scalar::zero() {
            composer.add_input(Scalar::one())
        } else {
            composer.add_input(Scalar::zero())
        };
        // Conditionally assign `1/u` or `0` to z
        let mut z = composer.zero_var;
        if u != Scalar::zero() {
            // If u != zero -> `z = 1/u`
            // Otherways, `u = 0` as it was defined avobe.
            // Check inverse existance, otherways, err.
            if u.invert().is_none().into() {
                return Err(ScoreError::NonExistingInverse.into());
            };
            // Safe to unwrap here.
            z = composer.add_input(u.invert().unwrap());
        }
        // We can safely unwrap `u` now since we know that the inverse for `u` exists.
        // Now we need to check the following to ensure we can provide a boolean
        // result representing wether the rangeproof holds or not:
        // `u = Chi(x)`.
        // `u * z = 1 - y`.
        // `y * u = 0`.
        let one = composer.add_input(Scalar::one());
        composer.add_gate(
            one,
            zero_or_other,
            composer.zero_var,
            u,
            -Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
        );
        let one_min_y = composer.add(
            (Scalar::one(), one),
            (-Scalar::one(), y),
            Scalar::zero(),
            Scalar::zero(),
        );
        let u_times_z = composer.mul(u, one, z, Scalar::zero(), Scalar::zero());
        composer.assert_equal(one_min_y, u_times_z);
        let y_times_u = composer.mul(u, one, y, Scalar::zero(), Scalar::zero());
        composer.assert_equal(y_times_u, composer.zero_var);
        y
    };
    // 2.4. Finally, A rangeproof for y' checking it's between [0, Order of the ScalarField mod 2^128]. We will apply the complex
    // rangeproof too.
    let minus_one_mod_2_pow_128 = {
        let min_one = BigUint::from_bytes_le(&(-Scalar::one()).to_bytes());
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
        Scalar::one(),
        first_cond,
        second_cond,
        Scalar::zero(),
        Scalar::zero(),
    );
    // (r1 = |Fr|/2^128 AND Y' < |Fr| mod 2^128)
    let right_assign = composer.mul(
        Scalar::one(),
        third_cond,
        fourth_cond,
        Scalar::zero(),
        Scalar::zero(),
    );
    // left_assign XOR right_assign = 1
    // This is possible since condition 1. and 3. are mutually exclusive. That means
    // that if one is true, the other part of the equation will be false (0).
    // Therefore, we can apply a mul gate since the inputs are boolean and
    // both sides of the equal can't be true, but both can be false, and this has to make the proof fail.
    // The following gate computes the XOR and constraints the result to be equal to one.
    composer.add_gate(
        left_assign,
        right_assign,
        one,
        Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
        -Scalar::one(),
        Scalar::zero(),
    );

    // 3. r2 < Y' we need a 128-bit range_proof
    let should_be_1 = single_complex_range_proof(composer, bid.score.r2, bid.score.y_prime)?;
    // Check that the result of the range_proof is indeed 0 to assert it passed.
    composer.constrain_to_constant(should_be_1, Scalar::one(), Scalar::zero());

    // 4. f < 2^120
    composer.range_gate(score_var, 120usize);
    // 5. f*Y' + r2 -d*2^128 = 0
    //
    // f * Y'
    let f_y_prime_prod = composer.mul(
        Scalar::one(),
        score_var,
        y_prime,
        Scalar::zero(),
        Scalar::zero(),
    );
    // f*Y' + r2
    let left = composer.add(
        (Scalar::one(), f_y_prime_prod),
        (Scalar::one(), r2),
        Scalar::zero(),
        Scalar::zero(),
    );
    // (f*Y' + r2) - d*2^128 = 0
    composer.add_gate(
        left,
        bid_value,
        composer.zero_var,
        Scalar::one(),
        -two_pow_128,
        Scalar::zero(),
        Scalar::zero(),
        Scalar::zero(),
    );

    Ok(())
}

// Builds a complex range-proof (not bounded to a pow_of_two) given a
// composer, the max range and the witness.
fn single_complex_range_proof(
    composer: &mut StandardComposer,
    witness: Scalar,
    max_range: Scalar,
) -> Result<Variable, Error> {
    // The closest pow of two for Y' is 2^128
    let two_pow_128 = Scalar::from(2u64).pow(&[128u64, 0, 0, 0]);
    // Compute b' max range.
    let b_prime = two_pow_128 - max_range;
    // Obtain 128-bit representation of `witness + b'`.
    let bits = scalar_to_bits(&(witness + b_prime));

    let mut var_accumulator = composer.zero_var;
    let mut accumulator = Scalar::zero();

    bits[..129].iter().enumerate().for_each(|(idx, bit)| {
        let bit_var = composer.add_input(Scalar::from(*bit as u64));
        // Apply boolean constraint to the bit.
        composer.bool_gate(bit_var);
        // Accumulate the bit multiplied by 2^(i-1) as a variable
        var_accumulator = composer.add(
            (Scalar::one(), var_accumulator),
            (Scalar::from(2u64).pow(&[idx as u64, 0, 0, 0]), bit_var),
            Scalar::zero(),
            Scalar::zero(),
        );
        // Compute the same accumulator with scalars
        accumulator = accumulator
            + (Scalar::from(*bit as u64) * Scalar::from(2u64).pow(&[idx as u64, 0, 0, 0]));
    });
    // Compute `Chi(x)` =  Sum(vi * 2^(i-1)) - (x + b').
    let witness_plus_b_prime = composer.add_input(witness + b_prime);
    // Note that the result will be equal to: `0 (if the reangeproof holds)
    // or any other value if it doesn't.
    let chi_x_var = composer.add(
        (Scalar::one(), witness_plus_b_prime),
        (-Scalar::one(), var_accumulator),
        Scalar::zero(),
        Scalar::zero(),
    );
    // It is possible to replace a constraint $\chi(\mathbf{x})=0$ on variables $\mathbf{x}$
    // with a set of constraints $\psi$ on  new variables $(u,y,z)$ such
    // that $y=1$ if $\chi$ holds and $y=0$ otherwise.
    // We introduce new variables $u,y,z$ that are computed as follows:
    //
    // u &= \chi(\mathbf{x});\\
    // y &=\begin{cases}
    // 0,& \text{if }u\neq 0;\\
    // 1,& \text{if }u=0.
    // \end{cases}\\
    // z&=\begin{cases}
    // 1/u,& \text{if }u\neq 0;\\
    // 0,& \text{if }u=0.
    // \end{cases}
    let u = witness + b_prime - accumulator;
    // Conditionally assign `1` or `0` to `y`.
    let y = if u == Scalar::zero() {
        composer.add_input(Scalar::one())
    } else {
        composer.add_input(Scalar::zero())
    };
    // Conditionally assign `1/u` or `0` to z
    let mut z = composer.zero_var;
    if u != Scalar::zero() {
        // If u != zero -> `z = 1/u`
        // Otherways, `u = 0` as it was defined avobe.
        // Check inverse existance, otherways, err.
        if u.invert().is_none().into() {
            return Err(ScoreError::NonExistingInverse.into());
        };
        // Safe to unwrap here.
        z = composer.add_input(u.invert().unwrap());
    }
    // We can safely unwrap `u` now.
    // Now we need to check the following to ensure we can provide a boolean
    // result representing wether the rangeproof holds or not:
    // `u = Chi(x)`.
    // `u * z = 1 - y`.
    // `y * u = 0`.
    let one = composer.add_input(Scalar::one());
    composer.add_gate(
        one,
        chi_x_var,
        composer.zero_var,
        u,
        -Scalar::one(),
        Scalar::zero(),
        Scalar::zero(),
        Scalar::zero(),
    );
    let one_min_y = composer.add(
        (Scalar::one(), one),
        (-Scalar::one(), y),
        Scalar::zero(),
        Scalar::zero(),
    );
    let u_times_z = composer.mul(u, one, z, Scalar::zero(), Scalar::zero());
    composer.assert_equal(one_min_y, u_times_z);
    let y_times_u = composer.mul(u, one, y, Scalar::zero(), Scalar::zero());
    composer.assert_equal(y_times_u, composer.zero_var);
    // Constraint the result to be boolean
    composer.bool_gate(y);
    Ok(y)
}

// Given the y parameter, return the y' and it's inverse value.
fn biguint_to_scalar(biguint: BigUint) -> Result<Scalar, Error> {
    let mut bytes = [0u8; 32];
    let biguint_bytes = biguint.to_bytes_le();
    if biguint_bytes.len() > 32 {
        return Err(ScoreError::InvalidScoreFieldsLen.into());
    };
    bytes[0..biguint_bytes.len()].copy_from_slice(&biguint_bytes[..]);
    // Due to the previous conditions, we can unwrap here safely.
    Ok(Scalar::from_bytes(&bytes).unwrap())
}

fn scalar_to_bits(scalar: &Scalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();
    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::constraint_system::StandardComposer;
    use dusk_plonk::fft::EvaluationDomain;
    use jubjub::{AffinePoint, Fr as JubJubScalar};
    use merlin::Transcript;

    #[test]
    fn biguint_scalar_conversion() {
        let rand_scalar = Scalar::random(&mut rand::thread_rng());
        let big_uint = BigUint::from_bytes_le(&rand_scalar.to_bytes());

        assert_eq!(biguint_to_scalar(big_uint).unwrap(), rand_scalar)
    }

    #[test]
    fn correct_complex_rangeproof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        let res = single_complex_range_proof(
            &mut composer,
            Scalar::from(2u64).pow(&[127u64, 0, 0, 0]),
            Scalar::from(2u64).pow(&[128u64, 0, 0, 0]) - Scalar::one(),
        )
        .unwrap();
        // Constraint res to be true, since the range should hold.
        composer.constrain_to_constant(res, Scalar::one(), Scalar::zero());
        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();
        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(270).unwrap());

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        // This should pass since the range_proof holds.
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }

    #[test]
    fn wrong_complex_rangeproof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        let res = single_complex_range_proof(
            &mut composer,
            Scalar::from(2u64).pow(&[130u64, 0, 0, 0]),
            Scalar::from(2u64).pow(&[128u64, 0, 0, 0]) - Scalar::one(),
        )
        .unwrap();
        // Constraint res to be false, since the range should not hold.
        composer.constrain_to_constant(res, Scalar::zero(), Scalar::zero());
        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();

        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(270).unwrap());

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        // This should pass since the range_proof doesn't hold and we constrained the
        // boolean result of it to be false.
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }

    #[test]
    fn correct_score_gen_proof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        // Generate a correct Bid
        let bid = Bid::new(
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            JubJubScalar::from(99u64),
            JubJubScalar::from(6546546u64),
            Scalar::random(&mut rand::thread_rng()),
            AffinePoint::identity(),
        )
        .unwrap();
        prove_correct_score_gadget(&mut composer, &bid).unwrap();
        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();

        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(1099).unwrap());
        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }

    #[test]
    fn incorrect_score_gen_proof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        // Generate a correct Bid
        let mut bid = Bid::new(
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            JubJubScalar::from(99u64),
            JubJubScalar::from(6546546u64),
            Scalar::random(&mut rand::thread_rng()),
            AffinePoint::identity(),
        )
        .unwrap();
        // Edit score fields
        let mut score = bid.score;
        score.score = Scalar::from(5686536568u64);
        score.r1 = Scalar::from(5898956968u64);
        bid.score = score;
        prove_correct_score_gadget(&mut composer, &bid).unwrap();
        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();

        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(1099).unwrap());

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        assert!(!proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }
}
