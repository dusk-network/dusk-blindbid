//! BlindBidProof module.

use crate::bid::{Bid, StorageBid};
use crate::score_gen::*;
use anyhow::Result;
use dusk_plonk::constraint_system::ecc::{
    curve_addition, gates::*, scalar_mul,
};
use dusk_plonk::jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use poseidon252::{
    merkle_proof::merkle_opening_gadget, sponge::sponge::*, PoseidonBranch,
    StorageScalar,
};

/// Generates the proof of BlindBid
pub fn blind_bid_proof(
    composer: &mut StandardComposer,
    bid: &Bid,
    branch: &PoseidonBranch,
    value: JubJubScalar,
    blinder: JubJubScalar,
) -> Result<()> {
    // Get the corresponding `StorageBid` value that for the `Bid`
    // which is effectively the value of the proven leaf.
    let storage_bid = StorageBid::from(bid);
    let encoded_bid: StorageScalar = storage_bid.into();
    let proven_leaf = composer.add_input(encoded_bid.into());

    // 1. Merkle Opening
    merkle_opening_gadget(composer, branch.clone(), proven_leaf, branch.root);
    // 2. Bid pre_image check
    storage_bid.preimage_gadget(composer);
    // 3. k_t <= t_a range check XXX: Needs review!
    single_complex_range_proof(
        composer,
        BlsScalar::from(storage_bid.elegibility_ts as u64),
        bid.latest_consensus_step,
    )?;

    // 4. t_e <= k_t
    single_complex_range_proof(
        composer,
        BlsScalar::from(storage_bid.expiration_ts as u64),
        bid.latest_consensus_step,
    )?;

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
    use dusk_plonk::jubjub::{
        AffinePoint, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
    };
    use kelvin::Blake2b;
    use poseidon252::PoseidonTree;
    use rand_core::RngCore;

    pub(self) fn gen_val_blinder_and_commitment(
    ) -> (JubJubScalar, JubJubScalar, AffinePoint) {
        let value = JubJubScalar::from(235_000u64);
        let blinder = JubJubScalar::random(&mut rand::thread_rng());

        let commitment: AffinePoint = AffinePoint::from(
            &(GENERATOR_EXTENDED * value)
                + &(GENERATOR_NUMS_EXTENDED * blinder),
        );
        (value, blinder, commitment)
    }

    #[test]
    fn correct_blindbid_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        let (value, blinder, commitment) = gen_val_blinder_and_commitment();

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let bid = Bid {
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

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(prover.mut_cs(), &bid, &branch, value, blinder)?;
        //assert!(prover.mut_cs().circuit_size() == 49693);
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, value, blinder)?;
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

        let (value, blinder, commitment) = gen_val_blinder_and_commitment();

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

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
            hashed_secret: BlsScalar::random(&mut rand::thread_rng()),
            pk: AffinePoint::identity(),
            c: commitment,
        }
        .init(&value)?;

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
        blind_bid_proof(prover.mut_cs(), &bid, &branch, value, blinder)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, value, blinder)?;
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

        let (value, blinder, commitment) = gen_val_blinder_and_commitment();

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let bid = Bid {
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
            hashed_secret: BlsScalar::random(&mut rand::thread_rng()),
            pk: AffinePoint::identity(),
            c: commitment,
        }
        .init(&value)?;

        let value = JubJubScalar::from(2u64).pow(&[65, 0, 0, 0u64]);
        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(prover.mut_cs(), &bid, &branch, value, blinder)?;
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(verifier.mut_cs(), &bid, &branch, value, blinder)?;
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }
}
