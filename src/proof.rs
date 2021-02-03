// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! BlindBidProof module.
use crate::bid::score::Score;
use crate::bid::{encoding::preimage_gadget, Bid};
use anyhow::Result;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::Ownable;
use dusk_plonk::constraint_system::ecc::{
    scalar_mul::fixed_base::scalar_mul, Point,
};
use dusk_plonk::prelude::*;
use plonk_gadgets::{AllocatedScalar, RangeGadgets::max_bound};
use poseidon252::{
    sponge,
    tree::{merkle_opening as merkle_opening_gadget, PoseidonBranch},
};

#[derive(Debug, Clone)]
pub struct BlindBidCircuit<'a> {
    // Inputs of the circuit.
    pub bid: Bid,
    pub score: Score,
    // External fields needed by the circuit.
    pub secret_k: BlsScalar,
    pub seed: BlsScalar,
    pub latest_consensus_round: BlsScalar,
    pub latest_consensus_step: BlsScalar,
    pub branch: &'a PoseidonBranch<17>,
    // Required fields to decrypt Bid internal info.
    pub secret: JubJubAffine,
    pub trim_size: usize,
    pub pi_positions: Vec<PublicInput>,
}

impl<'a> Circuit<'a> for BlindBidCircuit<'a> {
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
        // Check if the inputs were indeed pre-loaded inside of the circuit
        // structure.
        let bid = self.bid;
        let branch = self.branch;
        let secret_k = self.secret_k;
        let seed = self.seed;
        let latest_consensus_round = self.latest_consensus_round;
        let latest_consensus_step = self.latest_consensus_step;
        let score = self.score;
        let secret = self.secret;
        // Instantiate PI vector.
        let pi = self.get_mut_pi_positions();
        // Get the corresponding `StorageBid` value that for the `Bid`
        // which is effectively the value of the proven leaf (hash of the Bid)
        // and allocate it.
        let storage_bid: BlsScalar = bid.into();
        let bid_hash = AllocatedScalar::allocate(composer, storage_bid);
        // Allocate Bid-internal fields
        let bid_hashed_secret =
            AllocatedScalar::allocate(composer, bid.hashed_secret());
        let bid_cipher = (
            composer.add_input(bid.encrypted_data().cipher()[0]),
            composer.add_input(bid.encrypted_data().cipher()[1]),
        );
        let bid_commitment =
            Point::from_private_affine(composer, bid.commitment());
        let bid_stealth_addr = (
            Point::from_private_affine(
                composer,
                bid.stealth_address().pk_r().as_ref().into(),
            ),
            Point::from_private_affine(
                composer,
                bid.stealth_address().R().into(),
            ),
        );
        let bid_eligibility_ts = AllocatedScalar::allocate(
            composer,
            BlsScalar::from(bid.eligibility()),
        );
        let bid_expiration = AllocatedScalar::allocate(
            composer,
            BlsScalar::from(bid.expiration()),
        );
        let pos =
            AllocatedScalar::allocate(composer, BlsScalar::from(bid.pos()));
        // Allocate bid-needed inputs
        let secret_k = AllocatedScalar::allocate(composer, secret_k);
        let seed = AllocatedScalar::allocate(composer, seed);
        let latest_consensus_step =
            AllocatedScalar::allocate(composer, latest_consensus_step);
        let latest_consensus_round =
            AllocatedScalar::allocate(composer, latest_consensus_round);
        // Decrypt the cypher using the secret and allocate value & blinder.
        // If the decryption fails, we just set the result to an
        // impossible-to-obtain value.
        // On that way, verifiers do not get stuck on the process (they don't
        // care) about the real values here (just about filling the
        // composer). And provers won't get any info about if this
        // secret can or not decrypt the cipher.
        let (value, blinder) = bid
            .decrypt_data(&secret)
            .unwrap_or((JubJubScalar::one(), JubJubScalar::one()));
        let bid_value = AllocatedScalar::allocate(composer, value.into());
        let bid_blinder = AllocatedScalar::allocate(composer, blinder.into());
        // Allocate the bid tree root to be used later by the score_generation
        // gadget.
        let bid_tree_root =
            AllocatedScalar::allocate(composer, branch.root().clone());

        // ------------------------------------------------------- //
        //                                                         //
        //                     BlindBid Circuit                    //
        //                                                         //
        // ------------------------------------------------------- //

        // 1. Merkle Opening
        let root = merkle_opening_gadget(composer, branch, bid_hash.var);
        // Add PI constraint for the root to the PI constructor
        pi.push(PublicInput::BlsScalar(
            -branch.root(),
            composer.circuit_size(),
        ));

        // Constraint the bid_tree_root against a PI that represents
        // the root of the Bid tree that lives inside of the `Bid` contract.
        composer.constrain_to_constant(root, BlsScalar::zero(), -branch.root());

        // 2. Bid pre_image check
        let computed_bid_hash = preimage_gadget(
            composer,
            bid_cipher,
            bid_commitment,
            bid_stealth_addr,
            bid_hashed_secret.var,
            bid_eligibility_ts.var,
            bid_expiration.var,
            pos.var,
        );

        // Add PI constraint for bid preimage check.
        pi.push(PublicInput::BlsScalar(
            -bid_hash.scalar,
            composer.circuit_size(),
        ));
        // Constraint the hash to be equal to the real one
        composer.constrain_to_constant(
            computed_bid_hash,
            BlsScalar::zero(),
            -bid_hash.scalar,
        );

        // 3. t_a >= k_t
        // k_t - t_a should be > 2^64 which is the max size of the round.
        let kt_min_ta = composer.add(
            (BlsScalar::one(), latest_consensus_round.var),
            (-BlsScalar::one(), bid_eligibility_ts.var),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let kt_min_ta_scalar =
            latest_consensus_round.scalar - bid_eligibility_ts.scalar;
        let kt_min_ta = AllocatedScalar {
            scalar: kt_min_ta_scalar,
            var: kt_min_ta,
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
        let kt_min_te = composer.add(
            (BlsScalar::one(), latest_consensus_round.var),
            (-BlsScalar::one(), bid_expiration.var),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let kt_min_te_scalar =
            latest_consensus_round.scalar - bid_expiration.scalar;
        let kt_min_te = AllocatedScalar {
            scalar: kt_min_te_scalar,
            var: kt_min_te,
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
        pi.push(PublicInput::AffinePoint(
            bid.commitment(),
            composer.circuit_size(),
            composer.circuit_size() + 1,
        ));

        // Assert computed_commitment == announced commitment.
        composer.assert_equal_public_point(computed_c, bid.commitment());

        // 6. 0 < value <= 2^64 range check
        // v < 2^64
        composer.range_gate(bid_value.var, 64usize);

        // 7. `m = H(k)` Secret key pre-image check.
        let secret_k_hash = sponge::gadget(composer, &[secret_k.var]);
        // Add PI constraint for the secret_k_hash.
        pi.push(PublicInput::BlsScalar(
            -bid.hashed_secret(),
            composer.circuit_size(),
        ));

        // Constraint the secret_k_hash to be equal to the publicly avaliable
        // one.
        composer.constrain_to_constant(
            secret_k_hash,
            BlsScalar::zero(),
            -bid.hashed_secret(),
        );

        // We generate the prover_id and constrain it to a public input
        // On that way we bind the Score to the correct id.
        // 8. `prover_id = H(secret_k, sigma^s, k^t, k^s)`. Preimage check
        let prover_id = sponge::gadget(
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
        pi.push(PublicInput::BlsScalar(
            -bid.generate_prover_id(
                secret_k.scalar,
                seed.scalar,
                latest_consensus_round.scalar,
                latest_consensus_step.scalar,
            ),
            composer.circuit_size(),
        ));
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
        let computed_score = score.prove_correct_score_gadget(
            composer,
            bid_value,
            secret_k,
            bid_tree_root,
            seed,
            latest_consensus_round,
            latest_consensus_step,
        );

        // Constraint the score to be the public one and set it in the PI
        // constructor.
        pi.push(PublicInput::BlsScalar(
            -score.value(),
            composer.circuit_size(),
        ));
        composer.constrain_to_constant(
            computed_score,
            BlsScalar::zero(),
            -score.value(),
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
