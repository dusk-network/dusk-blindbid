// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for
// details.”
//! BlindBidProof module.

use crate::bid::{encoding::preimage_gadget, Bid};
use crate::score_gen::*;
use anyhow::{Error, Result};
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

#[derive(Debug, Default, Clone)]
pub struct BlindBidCircuit<'a> {
    // Inputs of the circuit.
    pub bid: Option<Bid>,
    pub score: Option<Score>,
    // External fields needed by the circuit.
    pub secret_k: Option<BlsScalar>,
    pub seed: Option<BlsScalar>,
    pub latest_consensus_round: Option<BlsScalar>,
    pub latest_consensus_step: Option<BlsScalar>,
    pub branch: Option<&'a PoseidonBranch>,
    // Required fields to decrypt Bid internal info.
    pub secret: Option<AffinePoint>,
    pub size: usize,
    pub pi_constructor: Option<Vec<PublicInput>>,
}

impl<'a> Circuit<'a> for BlindBidCircuit<'a> {
    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
    ) -> Result<Vec<PublicInput>, Error> {
        // Instanciate PI vector.
        let mut pi = Vec::new();
        // Generate constant witness values for 0.
        let zero =
            composer.add_witness_to_circuit_description(BlsScalar::zero());
        // Check if the inputs were indeed pre-loaded inside of the circuit
        // structure.
        let bid = self
            .bid
            .as_ref()
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        let branch = self
            .branch
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        let secret_k = self
            .secret_k
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        let seed = self
            .seed
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        let latest_consensus_round = self
            .latest_consensus_round
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        let latest_consensus_step = self
            .latest_consensus_step
            .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
        // Get the corresponding `StorageBid` value that for the `Bid`
        // which is effectively the value of the proven leaf (hash of the Bid)
        // and allocate it.
        let bid_hash =
            AllocatedScalar::allocate(composer, StorageScalar::from(bid).0);
        // Allocate Bid-internal fields
        let bid_hashed_secret =
            AllocatedScalar::allocate(composer, bid.hashed_secret);
        let bid_cipher = (
            composer.add_input(bid.encrypted_data.cipher()[0]),
            composer.add_input(bid.encrypted_data.cipher()[1]),
        );
        let bid_commitment = Point::from_private_affine(composer, bid.c);
        let bid_stealth_addr = (
            Point::from_private_affine(
                composer,
                bid.stealth_address.pk_r().into(),
            ),
            Point::from_private_affine(
                composer,
                bid.stealth_address.R().into(),
            ),
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
        // Decrypt the cypher using the secret and allocate value & blinder
        let decrypted_data = bid.encrypted_data.decrypt(
            self.secret
                .as_ref()
                .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?,
            &bid.nonce,
        )?;
        let bid_value = AllocatedScalar::allocate(composer, decrypted_data[0]);
        let bid_blinder =
            AllocatedScalar::allocate(composer, decrypted_data[1]);
        // Allocate the bid tree root to be used later by the score_generation
        // gadget.
        let bid_tree_root = AllocatedScalar::allocate(composer, branch.root);

        // ------------------------------------------------------- //
        //                                                         //
        //                     BlindBid Circuit                    //
        //                                                         //
        // ------------------------------------------------------- //

        // 1. Merkle Opening
        let root = merkle_opening_gadget(
            composer,
            branch.clone(),
            bid_hash.var,
            branch.root,
        );
        // Add PI constraint for the root to the PI constructor
        pi.push(PublicInput::BlsScalar(
            -branch.root,
            composer.circuit_size(),
        ));
        // Constraint the bid_tree_root against a PI that represents
        // the root of the Bid tree that lives inside of the `Bid` contract.
        composer.constrain_to_constant(root, BlsScalar::zero(), -branch.root);

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
        let third_cond = max_bound(
            composer,
            latest_consensus_round.scalar,
            bid_elegibility_ts,
        )
        .0;
        // We should get a 0 if t_e is greater, but we need this to be one in
        // order to hold. Therefore we conditionally select one.
        let third_cond = conditionally_select_one(composer, zero, third_cond);
        // Constraint third condition to be true.
        // So basically, that the rangeproofs hold.
        composer.constrain_to_constant(
            third_cond,
            BlsScalar::one(),
            BlsScalar::zero(),
        );

        // 4. t_e >= k_t
        let fourth_cond = max_bound(
            composer,
            latest_consensus_round.scalar,
            bid_expiration_ts,
        )
        .0;
        // We should get a 0 if t_e is greater, but we need this to be one in
        // order to hold. Therefore we conditionally select one.
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
        // Add PI constraint for the commitment computation check.
        pi.push(PublicInput::AffinePoint(
            bid.c,
            composer.circuit_size(),
            composer.circuit_size() + 1,
        ));
        // Assert computed_commitment == announced commitment.
        composer.assert_equal_public_point(computed_c, bid.c);

        // 6. 0 < value <= 2^64 range check
        // v < 2^64
        composer.range_gate(bid_value.var, 64usize);

        // 7. `m = H(k)` Secret key pre-image check.
        let secret_k_hash = sponge_hash_gadget(composer, &[secret_k.var]);
        // Add PI constraint for the secret_k_hash.
        pi.push(PublicInput::BlsScalar(
            -bid.hashed_secret,
            composer.circuit_size(),
        ));
        // Constraint the secret_k_hash to be equal to the publicly avaliable
        // one.
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
        prove_correct_score_gadget(
            composer,
            self.score
                .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?,
            bid_value,
            secret_k,
            bid_tree_root,
            seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;
        // Set the final circuit size as a Circuit struct attribute.
        self.size = composer.circuit_size();
        Ok(pi)
    }

    fn compile(
        &mut self,
        pub_params: &PublicParameters,
    ) -> Result<(ProverKey, VerifierKey, usize), Error> {
        // Setup PublicParams
        let (ck, _) = pub_params.trim(1 << 16)?;
        // Generate & save `ProverKey` with some random values.
        let mut prover = Prover::new(b"TestCircuit");
        // Set size & Pi builder
        self.pi_constructor = Some(self.gadget(prover.mut_cs())?);
        prover.preprocess(&ck)?;

        // Generate & save `VerifierKey` with some random values.
        let mut verifier = Verifier::new(b"TestCircuit");
        self.gadget(verifier.mut_cs())?;
        verifier.preprocess(&ck)?;
        Ok((
            prover
                .prover_key
                .expect("Unexpected error. Missing VerifierKey in compilation")
                .clone(),
            verifier
                .verifier_key
                .expect("Unexpected error. Missing VerifierKey in compilation"),
            self.circuit_size(),
        ))
    }

    fn build_pi(&self, pub_inputs: &[PublicInput]) -> Result<Vec<BlsScalar>> {
        let mut pi = vec![BlsScalar::zero(); self.size];
        self.pi_constructor
            .as_ref()
            .ok_or(CircuitErrors::CircuitInputsNotFound)?
            .iter()
            .enumerate()
            .for_each(|(idx, pi_constr)| {
                match pi_constr {
                    PublicInput::BlsScalar(_, pos) => {
                        pi[*pos] = pub_inputs[idx].value()[0]
                    }
                    PublicInput::JubJubScalar(_, pos) => {
                        pi[*pos] = pub_inputs[idx].value()[0]
                    }
                    PublicInput::AffinePoint(_, pos_x, pos_y) => {
                        let (coord_x, coord_y) = (
                            pub_inputs[idx].value()[0],
                            pub_inputs[idx].value()[1],
                        );
                        pi[*pos_x] = -coord_x;
                        pi[*pos_y] = -coord_y;
                    }
                };
            });
        Ok(pi)
    }

    fn circuit_size(&self) -> usize {
        self.size
    }

    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        transcript_initialisation: &'static [u8],
    ) -> Result<Proof> {
        let (ck, _) = pub_params.trim(1 << 16)?;
        // New Prover instance
        let mut prover = Prover::new(transcript_initialisation);
        // Fill witnesses for Prover
        self.gadget(prover.mut_cs())?;
        // Add ProverKey to Prover
        prover.prover_key = Some(prover_key.clone());
        prover.prove(&ck)
    }

    fn verify_proof(
        &mut self,
        pub_params: &PublicParameters,
        verifier_key: &VerifierKey,
        transcript_initialisation: &'static [u8],
        proof: &Proof,
        pub_inputs: &[PublicInput],
    ) -> Result<(), Error> {
        let (_, vk) = pub_params.trim(1 << 16)?;
        // New Verifier instance
        let mut verifier = Verifier::new(transcript_initialisation);
        // Fill witnesses for Verifier
        self.gadget(verifier.mut_cs())?;
        verifier.verifier_key = Some(*verifier_key);
        verifier.verify(proof, &vk, &self.build_pi(pub_inputs)?)
    }
}
