#![allow(non_snake_case)]
use anyhow::{Error, Result};
use blind_bid::bid::Bid;
use blind_bid::proof::blind_bid_proof;
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::jubjub::{AffinePoint, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use rand::Rng;

const V_RAW_MIN: u64 = 50_000u64;
const V_RAW_MAX: u64 = 250_000u64;

fn random_bid(
    secret: &JubJubScalar,
    secret_k: BlsScalar,
) -> Result<Bid, Error> {
    let mut rng = rand::thread_rng();
    let pk_r = PublicSpendKey::from(SecretSpendKey::default());
    let stealth_addr = pk_r.gen_stealth_address(&secret);
    let secret = GENERATOR_EXTENDED * secret;
    let value: u64 =
        (&mut rand::thread_rng()).gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
    let value = JubJubScalar::from(value);
    // Set the timestamps as the max values so the proofs do not fail for them
    // (never expired or non-elegible).
    let elegibility_ts = -BlsScalar::from(90u64);
    let expiration_ts = -BlsScalar::from(90u64);

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
mod protocol_tests {
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
        let mut tree: PoseidonTree<Bid, _> = PoseidonTree::new(17usize);

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret, secret_k)?;
        let secret: AffinePoint = (GENERATOR_EXTENDED * &secret).into();
        // Generate fields for the Bid & required by the compute_score
        let consensus_round_seed = BlsScalar::random(&mut rand::thread_rng());
        let latest_consensus_round = BlsScalar::from(50u64);
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
        for input in pi.iter().enumerate() {
            if input.1 != &BlsScalar::zero() {
                println!("{}", input.0);
            }
        }
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
            branch.root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )?;

        // Edit the Score so that we try to get a bigger one than the one we
        // should have got.
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
        let secret = JubJubScalar::random(&mut rng);
        let pk_r = PublicSpendKey::from(SecretSpendKey::default());
        let stealth_addr = pk_r.gen_stealth_address(&secret);
        let secret = AffinePoint::from(GENERATOR_EXTENDED * secret);
        let secret_k = BlsScalar::random(&mut rng);
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);
        let expiration_ts = BlsScalar::from(100u64);
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

        // We first generate the score as if the bid wasn't expired. Otherways
        // the score generation would fail since the Bid would be expired.
        let latest_consensus_round = BlsScalar::from(3u64);
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

        // Latest consensus step should be lower than the expiration_ts, in this
        // case is not so the proof should fail since the Bid is expired
        // at this round.
        let latest_consensus_round = BlsScalar::from(200u64);

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

        let mut pi = verifier.mut_cs().public_inputs.clone();
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }

    #[test]
    fn non_elegible_bid() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a PoseidonTree and append the Bid.
        let mut tree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17usize);

        // Create a non-elegible Bid.
        let mut rng = rand::thread_rng();
        let secret = JubJubScalar::random(&mut rng);
        let pk_r = PublicSpendKey::from(SecretSpendKey::default());
        let stealth_addr = pk_r.gen_stealth_address(&secret);
        let secret = AffinePoint::from(GENERATOR_EXTENDED * secret);
        let secret_k = BlsScalar::random(&mut rng);
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);
        let expiration_ts = BlsScalar::from(100u64);
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

        // We first generate the score as if the bid was still eligible.
        // Otherways the score generation would fail since the Bid
        // wouldn't be elegible.
        let latest_consensus_round = BlsScalar::from(3u64);
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

        // Latest consensus step should be lower than the elegibility_ts, in
        // this case is not so the proof should fail since the Bid is
        // non elegible anymore.
        let latest_consensus_round = BlsScalar::from(200u64);

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
        // The proof should fail since it is non elegible.
        assert!(verifier.verify(&proof, &vk, &pi).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;
    use poseidon252::StorageScalar;

    #[test]
    fn from_to_bytes_impl_works() -> Result<()> {
        let bid = random_bid(&JubJubScalar::one(), BlsScalar::one())?;
        let bid_hash: StorageScalar = bid.into();
        let bytes = bid.to_bytes();
        let bid2 = Bid::from_bytes(bytes)?;
        let bid_hash_2: StorageScalar = bid2.into();
        assert_eq!(bid_hash.0, bid_hash_2.0);
        Ok(())
    }
}
