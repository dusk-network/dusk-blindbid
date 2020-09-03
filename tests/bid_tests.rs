#![allow(non_snake_case)]
use anyhow::{Error, Result};
use blind_bid::bid::Bid;
use blind_bid::proof::blind_bid_proof;
use dusk_pki::StealthAddress;
use dusk_plonk::jubjub::{AffinePoint, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use rand::Rng;
use std::convert::TryFrom;

const V_RAW_MIN: u64 = 50_000u64;
const V_RAW_MAX: u64 = 250_000u64;

fn random_bid(
    secret: &JubJubScalar,
    secret_k: BlsScalar,
) -> Result<Bid, Error> {
    let mut rng = rand::thread_rng();

    let secret = GENERATOR_EXTENDED * secret;
    let value: u64 =
        (&mut rand::thread_rng()).gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
    let value = JubJubScalar::from(value);
    let pk_r =
        AffinePoint::from(GENERATOR_EXTENDED * JubJubScalar::random(&mut rng));
    let R =
        AffinePoint::from(GENERATOR_EXTENDED * JubJubScalar::random(&mut rng));
    let mut stealth_addr_buff = [0u8; 64];
    stealth_addr_buff[0..32].copy_from_slice(&pk_r.to_bytes()[..]);
    stealth_addr_buff[32..].copy_from_slice(&R.to_bytes()[..]);
    let stealth_addr = StealthAddress::try_from(&stealth_addr_buff)?;
    let elegibility_ts = BlsScalar::random(&mut rng);
    let expiration_ts = BlsScalar::random(&mut rng);

    Bid::new(
        &mut rng,
        &stealth_addr,
        &value,
        &secret.into(),
        secret_k,
        elegibility_ts,
        expiration_ts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret, secret_k)?;
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();
        // Generate fields for the Bid & required by the compute_score
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_step = BlsScalar::random(&mut rand::thread_rng());

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(bid.into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Generate a `Score` for our Bid with the consensus parameters
        let score = bid.compute_score(
            &secret,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(
            prover.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;

        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(
            verifier.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;
        verifier.preprocess(&ck)?;

        let pi = verifier.mut_cs().public_inputs.clone();
        verifier.verify(&proof, &vk, &pi)
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
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret, secret_k)?;
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();
        // Generate fields for the Bid & required by the compute_score
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_step = BlsScalar::random(&mut rand::thread_rng());

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(bid.into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Generate a `Score` for our Bid with the consensus parameters
        let mut score = bid.compute_score(
            &secret,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Edit the Score so that we try to get a bigger one than the one we should have got.
        score.score = score.score + BlsScalar::from(100u64);

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(
            prover.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;

        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(
            verifier.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;
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
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let mut bid = random_bid(&secret, secret_k)?;
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();
        // Generate fields for the Bid & required by the compute_score
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_step = BlsScalar::random(&mut rand::thread_rng());

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(bid.into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Generate a `Score` for our Bid with the consensus parameters
        let score = bid.compute_score(
            &secret,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Edit the Bid in order to cheat and get a bigger Score/whatever.
        bid.hashed_secret = BlsScalar::from(63463245u64);

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(
            prover.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;

        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(
            verifier.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;
        verifier.preprocess(&ck)?;

        let pi = verifier.mut_cs().public_inputs.clone();
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }

    #[test]
    fn expired_bid_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Create an expired bid.
        let mut rng = rand::thread_rng();
        let secret = AffinePoint::from(
            GENERATOR_EXTENDED * JubJubScalar::random(&mut rng),
        );
        let secret_k = BlsScalar::random(&mut rng);
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);
        let pk_r = AffinePoint::from(
            GENERATOR_EXTENDED * JubJubScalar::random(&mut rng),
        );
        let R = AffinePoint::from(
            GENERATOR_EXTENDED * JubJubScalar::random(&mut rng),
        );
        let mut stealth_addr_buff = [0u8; 64];
        stealth_addr_buff[0..32].copy_from_slice(&pk_r.to_bytes()[..]);
        stealth_addr_buff[32..].copy_from_slice(&R.to_bytes()[..]);
        let stealth_addr = StealthAddress::try_from(&stealth_addr_buff)?;
        let expiration_ts = BlsScalar::from(95u64);
        let elegibility_ts = BlsScalar::from(1000u64);
        let bid = Bid::new(
            &mut rng,
            &stealth_addr,
            &value,
            &secret.into(),
            secret_k,
            elegibility_ts,
            expiration_ts,
        )?;

        // Append the StorageBid as an StorageScalar to the tree.
        tree.push(bid.into())?;

        // Extract the branch
        let branch = tree
            .poseidon_branch(0u64)?
            .expect("Poseidon Branch Extraction");

        // Latest consensus step should be lower than the expiration_ts, in this case is not
        // so the proof should fail sincethe Bid expired.
        let latest_consensus_round = BlsScalar::from(90u64);
        let latest_consensus_step = BlsScalar::one();
        let consensus_round_seed = BlsScalar::random(&mut rng);

        // Generate a `Score` for our Bid with the consensus parameters
        let score = bid.compute_score(
            &secret,
            secret_k,
            branch.root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Proving
        let mut prover = Prover::new(b"testing");
        blind_bid_proof(
            prover.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;

        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        blind_bid_proof(
            verifier.mut_cs(),
            bid,
            score,
            &branch,
            &secret,
            secret_k,
            latest_consensus_step,
            latest_consensus_round,
            consensus_round_seed,
        )?;
        verifier.preprocess(&ck)?;

        let pi = verifier.mut_cs().public_inputs.clone();
        // The proof should fail since it is expired.
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }
}
