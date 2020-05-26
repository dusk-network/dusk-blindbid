//! Score generation

use crate::bid::Bid;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use jubjub::{AffinePoint, Scalar as JubJubScalar};
use poseidon252::sponge::*;

pub fn compute_score(bid: &Bid) -> Scalar {
    // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed, latest_consensus_round, latest_consensus_step)`.
    let y = sponge::sponge_hash(&[
        Scalar::from_bytes(&bid.secret_k.to_bytes()).unwrap(),
        bid.bid_tree_root,
        bid.consensus_round_seed,
        bid.latest_consensus_round,
        bid.latest_consensus_step,
    ]);
    // Compute y' and 1/y'.
    let (_, inv_y_prime) = compute_y_primes(y);
    // Return the score `q = v*2^128 / y'`.
    bid.value * Scalar::from(2u64).pow(&[128, 0, 0, 0]) * inv_y_prime
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
    // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed, latest_consensus_round, latest_consensus_step)`.
    // This is done in ZK using the sponge hash gadget.
    let y = sponge::sponge_hash_gadget(
        composer,
        &[
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ],
    );
    // We also need to compute the sponge hash with the scalars since we need to prove the correctness of the inverse
    // of y'.
    let scalar_y = sponge::sponge_hash(&[
        // We wrap up the JubJubScalar as a BlsScalar which will always fit.
        // That means that the unwrap is safe.
        Scalar::from_bytes(&bid.secret_k.to_bytes()).unwrap(),
        bid.bid_tree_root,
        bid.consensus_round_seed,
        bid.latest_consensus_round,
        bid.latest_consensus_step,
    ]);
    // Compute 1/y' where `y' = y & 2^129 -1`. This needs to be done for `Scalar` and `Variable` backends
    // to then assert that the inverse is correct.
    // Compute y' and 1/y'.
    let (_, inv_y_prime_scalar) = compute_y_primes(scalar_y);

    // Compute y' as a Variable.
    let y_prime_var = {
        let truncate_val =
            composer.add_input(Scalar::from(2u64).pow(&[129, 0, 0, 0]) - Scalar::one());
        composer.logic_and_gate(y, truncate_val, 256)
    };

    // Generate a Variable for 1/y'.
    let supposed_inv_y_prime = composer.add_input(inv_y_prime_scalar);
    // Check that 1/y' is indeed the inverse of y'.
    // To do that, we multiply the real 1/y' and the computed y' and subtract one.
    // This is indeed the constraint that verifies the integrity of the inverse.
    //
    // We don't need the input since it should be 0. If it is not, the verification process
    // will fail.
    composer.mul(
        Scalar::one(),
        y_prime_var,
        supposed_inv_y_prime,
        -Scalar::one(),
        Scalar::zero(),
    );
    // Return the score `q = v*2^128 / y'`.
    composer.mul(
        Scalar::from(2u64).pow(&[128, 0, 0, 0]),
        bid_value,
        supposed_inv_y_prime,
        Scalar::zero(),
        Scalar::zero(),
    )
}

// Given the y parameter, return the y' and it's inverse value.
fn compute_y_primes(y: Scalar) -> (Scalar, Scalar) {
    // Compute y'
    let y_prime = y & (Scalar::from(2u64).pow(&[129, 0, 0, 0]) - Scalar::one());
    // Compute 1/y' where `y' = y & 2^129 -1`
    let inv_y_prime = y.invert().unwrap();
    (y_prime, inv_y_prime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_bls12_381::G1Affine;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::constraint_system::{StandardComposer, Variable};
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn gadget_score_is_scalar_score() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();

        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"Test");

        // Generate a `Bid` with computed `score`.
        let bid = Bid::new(
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            // XXX: Set to random as soon as https://github.com/dusk-network/jubjub/issues/4
            // gets closed.
            JubJubScalar::one(),
            AffinePoint::identity(),
        );

        // Add as `Variable` to the composer the required values by the compute_score_gadget fn
        let bid_val_variable = composer.add_input(bid.value);
        // We wrap up the JubJubScalar as a BlsScalar which will always fit.
        // That means that the unwrap is safe.
        let secret_k_variable =
            composer.add_input(Scalar::from_bytes(&bid.secret_k.to_bytes()).unwrap());
        let consensus_round_seed_var = composer.add_input(bid.consensus_round_seed);
        let latest_consensus_step_var = composer.add_input(bid.latest_consensus_step);
        let latest_consensus_round_var = composer.add_input(bid.latest_consensus_round);

        // Compute the score using the compute_score_gadget fn
        let computed_score = compute_score_gadget(
            &mut composer,
            &bid,
            bid_val_variable,
            secret_k_variable,
            bid_val_variable,
            consensus_round_seed_var,
            latest_consensus_round_var,
            latest_consensus_step_var,
        );

        composer.constrain_to_constant(computed_score, bid.score.unwrap(), Scalar::zero());
        // Prove and Verify to check that indeed, the score is correct.
        composer.add_dummy_constraints();

        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(4096).unwrap());

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &vec![Scalar::zero()]));
    }
}
