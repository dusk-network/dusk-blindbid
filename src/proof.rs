//! BlindBidProof module.

use crate::bid::{Bid, StorageBid};
use crate::score_gen::*;
use anyhow::Result;
use dusk_plonk::constraint_system::ecc::{curve_addition, scalar_mul};
use dusk_plonk::jubjub::{
    AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use plonk_gadgets::{
    AllocatedScalar,
    RangeGadgets::{max_bound, range_check},
};
use poseidon252::{
    merkle_proof::merkle_opening_gadget, sponge::sponge::*, PoseidonBranch,
    StorageScalar,
};

/// Generates the proof of BlindBid
pub fn blind_bid_proof(
    composer: &mut StandardComposer,
    bid: &Bid,
    branch: &PoseidonBranch,
    secret: &AffinePoint,
) -> Result<()> {
    // Generate constant witness values for 0.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    // Get the corresponding `StorageBid` value that for the `Bid`
    // which is effectively the value of the proven leaf.
    let storage_bid = StorageBid::from(bid);
    let encoded_bid: StorageScalar = storage_bid.into();
    let proven_leaf = composer.add_input(encoded_bid.into());
    // Allocate bid-needed inputs
    let latest_consensus_step =
        AllocatedScalar::allocate(composer, bid.latest_consensus_step);
    let elegibility_ts = AllocatedScalar::allocate(
        composer,
        BlsScalar::from(bid.elegibility_ts as u64),
    );
    let expiration_ts = AllocatedScalar::allocate(
        composer,
        BlsScalar::from(bid.expiration_ts as u64),
    );

    // 1. Merkle Opening
    merkle_opening_gadget(composer, branch.clone(), proven_leaf, branch.root);
    // 2. Bid pre_image check
    storage_bid.preimage_gadget(composer);
    // 3. k_t <= t_a
    let third_cond = range_check(
        composer,
        latest_consensus_step.scalar,
        -BlsScalar::one(),
        elegibility_ts,
    ); // XXX: Does t_a have a max?

    // 4. t_e <= k_t
    let fourth_cond =
        max_bound(composer, latest_consensus_step.scalar, expiration_ts).0;
    // Constraint third and fourth conditions to be true.
    // So basically, that the rangeproofs hold.
    composer.poly_gate(
        third_cond,
        fourth_cond,
        zero,
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    let decrypted_data = bid.encrypted_data.decrypt(secret, &bid.nonce)?;
    let value = decrypted_data[0];
    let blinder = decrypted_data[1];

    // 5. c = C(v, b) Pedersen Commitment check
    let bid_value = composer.add_input(value.into());
    let blinder = composer.add_input(blinder.into());
    let p1 = scalar_mul(composer, bid_value, GENERATOR_EXTENDED);
    let p2 = scalar_mul(composer, blinder, GENERATOR_NUMS_EXTENDED);
    let computed_c = curve_addition(composer, p1.into(), p2.into());
    // Assert computed_commitment == announced commitment.
    composer.assert_equal_public_point(computed_c, bid.c);

    // 6. 0 < value <= 2^64 range check
    // Here is safe to unwrap since the order of the JubJub Scalar field is
    // shorter than the BLS12_381 one.
    let value = composer.add_input(value.into());
    // v < 2^64
    composer.range_gate(value, 64usize);

    // 7. `m = H(k)` Secret key pre-image check.
    let secret_k = composer.add_input(bid.secret_k);
    let secret_k_hash = sponge_hash_gadget(composer, &[secret_k]);
    // Constraint the secret_k_hash to be equal to the publicly avaliable one.
    composer.constrain_to_constant(
        secret_k_hash,
        BlsScalar::zero(),
        -sponge_hash(&[bid.secret_k]),
    );

    // 8. `prover_id = H(secret_k, sigma^s, k^t, k^s)`. Preimage check
    let sigma_s = composer.add_input(bid.consensus_round_seed);
    let k_t = composer.add_input(bid.latest_consensus_round);
    let k_s = composer.add_input(bid.latest_consensus_step);
    let prover_id =
        sponge_hash_gadget(composer, &[secret_k, sigma_s, k_t, k_s]);
    composer.constrain_to_constant(
        prover_id,
        BlsScalar::zero(),
        -bid.prover_id,
    );
    // 9. Score generation circuit check with the corresponding gadget.
    prove_correct_score_gadget(composer, bid, value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bid::bid::tests::random_bid;
    use dusk_plonk::jubjub::{AffinePoint, GENERATOR_EXTENDED};
    use kelvin::Blake2b;
    use poseidon252::PoseidonTree;

    #[test]
    fn correct_blindbid_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret);
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(prover.mut_cs(), &bid, &branch, &secret)?;
        //assert!(prover.mut_cs().circuit_size() == 49693);
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, &secret)?;
        verifier.preprocess(&ck)?;

        let pi = verifier.mut_cs().public_inputs.clone();
        verifier.verify(&proof, &vk, &pi)?;
        Ok(())
    }

    #[test]
    fn edited_score_blindbid_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let mut bid = random_bid(&secret);
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();

        // Edit the Bid structure to cheat by incrementing the Score.
        bid.score.score = -BlsScalar::one();
        // Edit the Bid structure by editing the expiration_ts.
        bid.expiration_ts = 13256586u32;
        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(prover.mut_cs(), &bid, &branch, &secret)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, &secret)?;
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }

    #[test]
    fn edited_bid_value_blindbid_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let mut bid = random_bid(&secret);
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();

        let value = crate::V_MAX + JubJubScalar::one();
        bid.set_value(&mut rand::thread_rng(), &value, &secret);

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(prover.mut_cs(), &bid, &branch, &secret)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, &secret)?;
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }
}
