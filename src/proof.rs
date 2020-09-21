// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for
// details.”
//! BlindBidProof module.

use crate::bid::{encoding::preimage_gadget, Bid};
use crate::score_gen::*;
use anyhow::Result;
use dusk_plonk::constraint_system::ecc::{
    scalar_mul::fixed_base::scalar_mul, Point,
};
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use plonk_gadgets::{
    AllocatedScalar, RangeGadgets::max_bound,
    ScalarGadgets::conditionally_select_one,
};
use poseidon252::{
    merkle_proof::merkle_opening_gadget, sponge::sponge::*, PoseidonBranch,
    StorageScalar,
};

/// Generates the proof of BlindBid
pub fn blind_bid_proof(
    composer: &mut StandardComposer,
    bid: Bid,
    score: Score,
    branch: &PoseidonBranch,
    secret: &AffinePoint,
    secret_k: BlsScalar,
    latest_consensus_step: BlsScalar,
    latest_consensus_round: BlsScalar,
    seed: BlsScalar,
) -> Result<()> {
    // Generate constant witness values for 0.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    // Get the corresponding `StorageBid` value that for the `Bid`
    // which is effectively the value of the proven leaf (hash of the Bid)
    // and allocate it.
    let bid_hash: StorageScalar = bid.into();
    let bid_hash = AllocatedScalar::allocate(composer, bid_hash.0);
    // Allocate Bid-internal fields
    let bid_hashed_secret =
        AllocatedScalar::allocate(composer, bid.hashed_secret);
    let bid_cipher = (
        composer.add_input(bid.encrypted_data.cipher()[0]),
        composer.add_input(bid.encrypted_data.cipher()[1]),
    );
    let bid_commitment = Point::from_private_affine(composer, bid.c);
    let bid_stealth_addr = (
        Point::from_private_affine(composer, bid.stealth_address.pk_r().into()),
        Point::from_private_affine(composer, bid.stealth_address.R().into()),
    );
    let bid_elegibility_ts =
        AllocatedScalar::allocate(composer, bid.elegibility_ts);
    let bid_expiration_ts =
        AllocatedScalar::allocate(composer, bid.expiration_ts);
    // Allocate bid-needed inputs
    let secret_k = AllocatedScalar::allocate(composer, secret_k);
    let seed = AllocatedScalar::allocate(composer, seed);
    let latest_consensus_step =
        AllocatedScalar::allocate(composer, latest_consensus_step);
    let latest_consensus_round =
        AllocatedScalar::allocate(composer, latest_consensus_round);
    let elegibility_ts =
        AllocatedScalar::allocate(composer, bid.elegibility_ts);
    let expiration_ts = AllocatedScalar::allocate(composer, bid.expiration_ts);
    // Decrypt the cypher using the secret and allocate value & blinder
    let decrypted_data = bid.encrypted_data.decrypt(secret, &bid.nonce)?;
    let bid_value = AllocatedScalar::allocate(composer, decrypted_data[0]);
    let bid_blinder = AllocatedScalar::allocate(composer, decrypted_data[1]);

    // Allocate the bid tree root to be used later by the score_generation
    // gadget.
    let bid_tree_root = AllocatedScalar::allocate(composer, branch.root);
    // Constraint the bid_tree_root against a PI that represents
    // the root of the Bid tree that lives inside of the `Bid` contract.
    composer.constrain_to_constant(
        bid_tree_root.var,
        BlsScalar::zero(),
        -branch.root,
    );

    // 1. Merkle Opening
    merkle_opening_gadget(composer, branch.clone(), bid_hash.var, branch.root);

    // 2. Bid pre_image check
    let computed_bid_hash = preimage_gadget(
        composer,
        bid_cipher,
        bid_commitment,
        bid_stealth_addr,
        bid_hashed_secret.var,
        bid_elegibility_ts.var,
        bid_expiration_ts.var,
    );

    // Constraint the hash to be equal to the real one
    composer.constrain_to_constant(
        computed_bid_hash,
        BlsScalar::zero(),
        -bid_hash.scalar,
    );

    // 3. t_a >= k_t
    let third_cond =
        max_bound(composer, latest_consensus_round.scalar, elegibility_ts).0;
    // We should get a 0 if t_e is greater, but we need this to be one in order
    // to hold. Therefore we conditionally select one.
    let third_cond = conditionally_select_one(composer, zero, third_cond);
    // Constraint third condition to be true.
    // So basically, that the rangeproofs hold.
    composer.constrain_to_constant(
        third_cond,
        BlsScalar::one(),
        BlsScalar::zero(),
    );

    // 4. t_e >= k_t
    let fourth_cond =
        max_bound(composer, latest_consensus_round.scalar, expiration_ts).0;
    // We should get a 0 if t_e is greater, but we need this to be one in order
    // to hold. Therefore we conditionally select one.
    let fourth_cond = conditionally_select_one(composer, zero, fourth_cond);
    // Constraint fourth condition to be true.
    // So basically, that the rangeproofs hold.
    composer.constrain_to_constant(
        fourth_cond,
        BlsScalar::one(),
        BlsScalar::zero(),
    );

    // 5. c = C(v, b) Pedersen Commitment check
    let p1 = scalar_mul(composer, bid_value.var, GENERATOR_EXTENDED);
    let p2 = scalar_mul(composer, bid_blinder.var, GENERATOR_NUMS_EXTENDED);
    let computed_c = p1.point().fast_add(composer, *p2.point());
    // Assert computed_commitment == announced commitment.
    composer.assert_equal_public_point(computed_c, bid.c);

    // 6. 0 < value <= 2^64 range check
    // v < 2^64
    composer.range_gate(bid_value.var, 64usize);

    // 7. `m = H(k)` Secret key pre-image check.
    let secret_k_hash = sponge_hash_gadget(composer, &[secret_k.var]);
    // Constraint the secret_k_hash to be equal to the publicly avaliable one.
    composer.constrain_to_constant(
        secret_k_hash,
        BlsScalar::zero(),
        -bid.hashed_secret,
    );

    // We generate the prover_id and constrain it to a public input
    // On that way we bind the Score to the correct id.
    // 8. `prover_id = H(secret_k, sigma^s, k^t, k^s)`. Preimage check
    let prover_id = sponge_hash_gadget(
        composer,
        &[
            secret_k.var,
            seed.var,
            latest_consensus_round.var,
            latest_consensus_step.var,
        ],
    );
    composer.constrain_to_constant(
        prover_id,
        BlsScalar::zero(),
        -bid.generate_prover_id(
            secret_k.scalar,
            seed.scalar,
            latest_consensus_round.scalar,
            latest_consensus_step.scalar,
        ),
    );
    // 9. Score generation circuit check with the corresponding gadget.
    prove_correct_score_gadget(
        composer,
        score,
        bid_value,
        secret_k,
        bid_tree_root,
        seed,
        latest_consensus_round,
        latest_consensus_step,
    )?;
    Ok(())
}
