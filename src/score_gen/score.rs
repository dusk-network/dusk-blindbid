//! Score generation

use crate::bid::Bid;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use poseidon252::sponge::*;

pub fn compute_score(bid: &Bid) -> Scalar {
    // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed, latest_consensus_round, latest_consensus_step)`.
    let y = sponge::sponge_hash(&[
        bid.secret_k,
        bid.bid_tree_root,
        bid.consensus_round_seed,
        bid.latest_consensus_round,
        bid.latest_consensus_step,
    ]);
    // Compute y' and 1/y'.
    let (_, inv_y_prime) = compute_y_primes(y);
    // Return the score `q = v*2^128 / y'`.
    bid.bid_value * Scalar::from(2u64).pow(&[128, 0, 0, 0]) * inv_y_prime
}

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
        bid.secret_k,
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
