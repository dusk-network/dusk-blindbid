// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! BlindBidProof module.

use crate::bid::Bid;
use crate::score_gen::*;
use crate::tree::DEPTH;
use anyhow::Result;
use dusk_plonk::constraint_system::ecc::scalar_mul::fixed_base::scalar_mul;
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use plonk_gadgets::{AllocatedScalar, RangeGadgets::max_bound};
use poseidon252::sponge::sponge::sponge_hash_gadget;
use poseidon252::tree::zk::merkle_opening;
use poseidon252::tree::PoseidonBranch;

#[derive(Debug, Clone)]
pub struct BlindBidCircuit {
    // Inputs of the circuit.
    pub bid: Bid,
    pub score: Score,
    // External fields needed by the circuit.
    pub secret_k: BlsScalar,
    pub seed: BlsScalar,
    pub latest_consensus_round: u64,
    pub latest_consensus_step: BlsScalar,
    pub branch: PoseidonBranch<DEPTH>,
    // Required fields to decrypt Bid internal info.
    pub secret: AffinePoint,
    pub trim_size: usize,
    pub pi_positions: Vec<PublicInput>,
}

impl Circuit<'_> for BlindBidCircuit {
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
        // Check if the inputs were indeed pre-loaded inside of the circuit
        // structure.
        let branch = self.branch;
        let secret_k = self.secret_k;
        let seed = self.seed;
        let latest_consensus_step = self.latest_consensus_step;
        let score = self.score;
        let secret = self.secret;

        let bid = self.bid.zk(composer);

        // Allocate bid-needed inputs
        let secret_k = AllocatedScalar::allocate(composer, secret_k);
        let seed = AllocatedScalar::allocate(composer, seed);
        let latest_consensus_step =
            AllocatedScalar::allocate(composer, latest_consensus_step);

        let latest_consensus_round = AllocatedScalar {
            scalar: BlsScalar::from(self.latest_consensus_round),
            var: composer
                .add_input(BlsScalar::from(self.latest_consensus_round)),
        };

        // Decrypt the cypher using the secret and allocate value & blinder.
        // If the decryption fails, we just set the result to an
        // impossible-to-obtain value.
        // On that way, verifiers do not get stuck on the process (they don't
        // care) about the real values here (just about filling the
        // composer). And provers won't get any info about if this
        // secret can or not decrypt the cipher.
        let decrypted_data = self
            .bid
            .encrypted_data
            .decrypt(&secret, &self.bid.nonce)
            .unwrap_or([BlsScalar::one(), BlsScalar::one()]);
        let bid_value = AllocatedScalar::allocate(composer, decrypted_data[0]);
        let bid_blinder =
            AllocatedScalar::allocate(composer, decrypted_data[1]);
        // Allocate the bid tree root to be used later by the score_generation
        // gadget.
        let bid_tree_root = AllocatedScalar::allocate(composer, branch.root());

        // ------------------------------------------------------- //
        //                                                         //
        //                     BlindBid Circuit                    //
        //                                                         //
        // ------------------------------------------------------- //

        // 1 and 2. Merkle Opening and Pre-Image
        let bid_hash = bid.preimage(composer);
        let root = merkle_opening(composer, &branch, bid_hash);

        // Add PI constraint for the root to the PI constructor
        self.pi_positions.push(PublicInput::BlsScalar(
            -branch.root(),
            composer.circuit_size(),
        ));
        // Constraint the bid_tree_root against a PI that represents
        // the root of the Bid tree that lives inside of the `Bid` contract.
        composer.constrain_to_constant(root, BlsScalar::zero(), -branch.root());

        // 3. t_a >= k_t
        // k_t - t_a should be > 2^64 which is the max size of the round.
        let kt_min_ta_var = composer.add(
            (BlsScalar::one(), latest_consensus_round.var),
            (-BlsScalar::one(), bid.eligibility),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let kt_min_ta =
            BlsScalar::from(self.latest_consensus_round - self.bid.eligibility);
        let kt_min_ta = AllocatedScalar {
            scalar: kt_min_ta,
            var: kt_min_ta_var,
        };
        // Third cond should be one since the range should fail since the op
        // should be < 0 and therefore become really big.
        let third_cond = max_bound(
            composer,
            BlsScalar::from(2u64).pow(&[64, 0, 0, 0]),
            kt_min_ta,
        )
        .0;
        // Constraint third condition to be one.
        // So basically, that the rangeproof does not hold.
        composer.constrain_to_constant(
            third_cond,
            BlsScalar::one(),
            BlsScalar::zero(),
        );

        // 4. t_e >= k_t
        // k_t - t_e should be > 2^64 which is the max size of the round.
        let kt_min_te_var = composer.add(
            (BlsScalar::one(), latest_consensus_round.var),
            (-BlsScalar::one(), bid.expiration),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let kt_min_te =
            BlsScalar::from(self.latest_consensus_round - self.bid.expiration);
        let kt_min_te = AllocatedScalar {
            scalar: kt_min_te,
            var: kt_min_te_var,
        };
        // Third cond should be one since the range should fail since the op
        // should be < 0 and therefore become really big.
        let fourth_cond = max_bound(
            composer,
            BlsScalar::from(2u64).pow(&[64, 0, 0, 0]),
            kt_min_te,
        )
        .0;
        // Constraint third condition to be one.
        // So basically, that the rangeproof does not hold.
        composer.constrain_to_constant(
            fourth_cond,
            BlsScalar::one(),
            BlsScalar::zero(),
        );

        // 5. c = C(v, b) Pedersen Commitment check
        let p1 = scalar_mul(composer, bid_value.var, GENERATOR_EXTENDED);
        let p2 = scalar_mul(composer, bid_blinder.var, GENERATOR_NUMS_EXTENDED);
        let computed_c = p1.point().fast_add(composer, *p2.point());
        // Add PI constraint for the commitment computation check.
        self.pi_positions.push(PublicInput::AffinePoint(
            self.bid.c,
            composer.circuit_size(),
            composer.circuit_size() + 1,
        ));

        // Assert computed_commitment == announced commitment.
        composer.assert_equal_public_point(computed_c, self.bid.c);

        // 6. 0 < value <= 2^64 range check
        // v < 2^64
        composer.range_gate(bid_value.var, 64usize);

        // 7. `m = H(k)` Secret key pre-image check.
        let secret_k_hash = sponge_hash_gadget(composer, &[secret_k.var]);
        // Add PI constraint for the secret_k_hash.
        self.pi_positions.push(PublicInput::BlsScalar(
            -self.bid.hashed_secret,
            composer.circuit_size(),
        ));

        // Constraint the secret_k_hash to be equal to the publicly avaliable
        // one.
        composer.constrain_to_constant(
            secret_k_hash,
            BlsScalar::zero(),
            -self.bid.hashed_secret,
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

        // Constraint the prover_id to be the public one and set it in the PI
        // constructor.
        let prover_id_scalar = self.bid.generate_prover_id(
            secret_k.scalar,
            seed.scalar,
            latest_consensus_round.scalar,
            latest_consensus_step.scalar,
        );
        self.pi_positions.push(PublicInput::BlsScalar(
            -prover_id_scalar,
            composer.circuit_size(),
        ));
        composer.constrain_to_constant(
            prover_id,
            BlsScalar::zero(),
            -prover_id_scalar,
        );

        // 9. Score generation circuit check with the corresponding gadget.
        let computed_score = prove_correct_score_gadget(
            composer,
            score,
            bid_value,
            secret_k,
            bid_tree_root,
            seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;
        // Constraint the score to be the public one and set it in the PI
        // constructor.
        self.pi_positions.push(PublicInput::BlsScalar(
            -score.score,
            composer.circuit_size(),
        ));
        composer.constrain_to_constant(
            computed_score,
            BlsScalar::zero(),
            -score.score,
        );

        Ok(())
    }

    fn get_pi_positions(&self) -> &Vec<PublicInput> {
        &self.pi_positions
    }

    fn get_mut_pi_positions(&mut self) -> &mut Vec<PublicInput> {
        &mut self.pi_positions
    }

    fn get_trim_size(&self) -> usize {
        self.trim_size
    }

    fn set_trim_size(&mut self, size: usize) {
        self.trim_size = size;
    }
}
