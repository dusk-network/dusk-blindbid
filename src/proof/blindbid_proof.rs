//! BlindBidProof module.
//!

use crate::bid::{Bid, StorageBid};
use crate::score_gen::*;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::StandardComposer;
use failure::Error;
use poseidon252::{
    merkle_proof::merkle_opening_gadget, sponge::sponge::*, PoseidonBranch, StorageScalar,
};

pub fn blind_bid_proof(
    composer: &mut StandardComposer,
    bid: &Bid,
    branch: &PoseidonBranch,
) -> Result<(), Error> {
    // Get the corresponding `StorageBid` value that for the `Bid`
    // which is effectively the value of the proven leaf.
    let storage_bid: StorageBid = StorageBid::from(bid).into();
    let encoded_bid: StorageScalar = storage_bid.into();
    let proven_leaf = composer.add_input(encoded_bid.into());
    // 1. Merkle Opening
    merkle_opening_gadget(composer, branch.clone(), proven_leaf, branch.root);
    // 2. Bid pre_image check
    storage_bid.preimage_gadget(composer);
    // 3. k_t <= t_a range check XXX: Needs review!
    single_complex_range_proof(
        composer,
        Scalar::from(bid.elegibility_ts as u64),
        bid.latest_consensus_step,
    )?;

    // 4. t_e <= k_t
    single_complex_range_proof(
        composer,
        Scalar::from(bid.expiration_ts as u64),
        bid.latest_consensus_step,
    )?;

    // 5. c = C(v, b) Pedersen Commitment check
    // XXX: Unimplemented until we have ECC gate.

    // 6. v_min < v <= v_max
    // 0 < v -> XXX: Needs review
    single_complex_range_proof(
        composer,
        Scalar::from(crate::v_min),
        Scalar::from_bytes(&bid.value.to_bytes()).unwrap(),
    )?;
    // v <= v_max
    single_complex_range_proof(
        composer,
        Scalar::from_bytes(&bid.value.to_bytes()).unwrap(),
        Scalar::from(crate::v_max),
    )?;

    // 7. 0 < value <= 2^64 range check
    // Here is safe to unwrap since the order of the JubJub scalar field is shorter than the
    // BLS12_381 one.
    let value = composer.add_input(Scalar::from_bytes(&bid.value.to_bytes()).unwrap());
    // v < 2^64
    composer.range_gate(value, 64usize);

    // 7. `m = H(k)` Secret key pre-image check.
    let secret_k = composer.add_input(bid.secret_k);
    let secret_k_hash = sponge_hash_gadget(composer, &[secret_k]);
    // Constraint the secret_k_hash to be equal to the publicly avaliable one.
    // This will introduce a Public Input to the circuit.
    composer.constrain_to_constant(secret_k_hash, Scalar::zero(), -sponge_hash(&[bid.secret_k]));

    // 8. `prover_id = H(secret_k, sigma^s, k^t, k^s)`. Preimage check
    let sigma_s = composer.add_input(bid.consensus_round_seed);
    let k_t = composer.add_input(bid.latest_consensus_round);
    let k_s = composer.add_input(bid.latest_consensus_step);
    let prover_id = sponge_hash_gadget(composer, &[secret_k, sigma_s, k_t, k_s]);
    // Constraint the computed prover_id to the expected & stored one.
    // This will introduce `prover_id` as a public input for the circuit.
    composer.constrain_to_constant(prover_id, Scalar::zero(), -bid.prover_id);

    // 9. Score generation circuit check with the corresponding gadget.
    prove_correct_score_gadget(composer, bid)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::constraint_system::StandardComposer;
    use dusk_plonk::fft::EvaluationDomain;
    use jubjub::{AffinePoint, Fr as JubJubScalar};
    use kelvin::Blake2b;
    use merlin::Transcript;
    use poseidon252::PoseidonTree;
    use rand_core::RngCore;

    #[test]
    fn correct_blindbid_proof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let bid = Bid::new(
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            rand::thread_rng().next_u32(),
            rand::thread_rng().next_u32(),
            JubJubScalar::from(99u64),
            JubJubScalar::from(199u64),
            JubJubScalar::from(6546546u64),
            JubJubScalar::from(655588855476u64),
            AffinePoint::identity(),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            AffinePoint::identity(),
            AffinePoint::identity(),
        )
        .unwrap();
        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into()).unwrap();

        // Extract the branch
        let branch = tree.poseidon_branch(0u64).unwrap().unwrap();

        blind_bid_proof(&mut composer, &bid, &branch).unwrap();
        println!("{:?}", composer.circuit_size());
        let prep_circ = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());

        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }

    #[test]
    fn incorrect_blindbid_proof() {
        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut composer = StandardComposer::new();
        let mut transcript = Transcript::new(b"TEST");

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let mut bid = Bid::new(
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            rand::thread_rng().next_u32(),
            rand::thread_rng().next_u32(),
            JubJubScalar::from(99u64),
            JubJubScalar::from(199u64),
            JubJubScalar::from(6546546u64),
            JubJubScalar::from(655588855476u64),
            AffinePoint::identity(),
            Scalar::random(&mut rand::thread_rng()),
            Scalar::random(&mut rand::thread_rng()),
            AffinePoint::identity(),
            AffinePoint::identity(),
        )
        .unwrap();
        // Edit the Bid structure to cheat by incrementing the Score.
        bid.score.score = -Scalar::one();
        // Edit the Bid structure by editing the expiration_ts.
        bid.expiration_ts = 13256586u32;
        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(StorageBid::from(&bid).into()).unwrap();

        // Extract the branch
        let branch = tree.poseidon_branch(0u64).unwrap().unwrap();

        blind_bid_proof(&mut composer, &bid, &branch).unwrap();
        let prep_circ = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());

        assert!(!proof.verify(&prep_circ, &mut transcript, &vk, &composer.public_inputs()));
    }
}
