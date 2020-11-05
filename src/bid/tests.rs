use crate::bid::Bid;
use anyhow::{Error, Result};
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::jubjub::GENERATOR_EXTENDED;
use dusk_plonk::prelude::*;
use rand::Rng;

fn random_bid(secret: &JubJubScalar) -> Result<Bid, Error> {
    let mut rng = rand::thread_rng();

    let secret_k = BlsScalar::from(*secret);
    let pk_r = PublicSpendKey::from(SecretSpendKey::default());
    let stealth_addr = pk_r.gen_stealth_address(&secret);
    let secret = GENERATOR_EXTENDED * secret;
    let value: u64 =
        (&mut rand::thread_rng()).gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
    let value = JubJubScalar::from(value);

    let eligibility = u64::max_value();
    let expiration = u64::max_value();

    Bid::new(
        &mut rng,
        &stealth_addr,
        &value,
        &secret.into(),
        secret_k,
        eligibility,
        expiration,
    )
}

#[test]
fn bid_preimage_gadget() -> Result<()> {
    const CAPACITY: usize = 1 << 12;

    // Generate Composer & Public Parameters
    let pub_params =
        PublicParameters::setup(CAPACITY, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(CAPACITY)?;

    // Generate a correct Bid
    let secret = JubJubScalar::random(&mut rand::thread_rng());
    let bid = random_bid(&secret)?;

    let circuit = |composer: &mut StandardComposer, bid: &Bid| {
        let bid_p = bid.zk(composer);
        let bid_p = bid_p.preimage(composer);

        composer.constrain_to_constant(bid_p, BlsScalar::zero(), -bid.hash());
    };

    // Proving
    let mut prover = Prover::new(b"testing");
    circuit(prover.mut_cs(), &bid);
    prover.preprocess(&ck)?;
    let proof = prover.prove(&ck)?;

    // Verification
    let mut verifier = Verifier::new(b"testing");
    circuit(verifier.mut_cs(), &bid);
    verifier.preprocess(&ck)?;
    let pi = verifier.mut_cs().public_inputs.clone();
    verifier.verify(&proof, &vk, &pi)
}
