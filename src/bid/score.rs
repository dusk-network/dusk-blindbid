// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Score generation

cfg_if::cfg_if! {
    if #[cfg(feature = "canon")] {
        use canonical::Canon;
        use canonical_derive::Canon;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use crate::errors::BlindBidError;
        use crate::bid::Bid;
        use dusk_jubjub::JubJubAffine;
        use dusk_plonk::prelude::*;
        use num_bigint::BigUint;
        use num_traits::{One, Zero};
        use poseidon252::sponge;use plonk_gadgets::{
            AllocatedScalar, RangeGadgets::max_bound, ScalarGadgets::maybe_equal,
};
    }
}

use core::ops::Deref;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]
/// The `Score` represents a "random" value obtained from the computations
/// based on blockchain data as well as [Bid](self::Bid) data.
/// It derefs to it's value although the structure contains more fields which
/// are side-results of this computation needed to proof the correctness of the
/// Score generation process later on.
pub struct Score {
    pub(crate) value: BlsScalar,
    y: BlsScalar,
    y_prime: BlsScalar,
    r1: BlsScalar,
    r2: BlsScalar,
}

impl Deref for Score {
    type Target = BlsScalar;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl AsRef<BlsScalar> for Score {
    fn as_ref(&self) -> &BlsScalar {
        &self.value
    }
}

impl Serializable<{ 5 * BlsScalar::SIZE }> for Score {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..BlsScalar::SIZE].copy_from_slice(&self.as_ref().to_bytes());
        buf[BlsScalar::SIZE..BlsScalar::SIZE * 2]
            .copy_from_slice(&self.as_ref().to_bytes());
        buf[BlsScalar::SIZE * 2..BlsScalar::SIZE * 3]
            .copy_from_slice(&self.as_ref().to_bytes());
        buf[BlsScalar::SIZE * 3..BlsScalar::SIZE * 4]
            .copy_from_slice(&self.as_ref().to_bytes());
        buf[BlsScalar::SIZE * 4..Self::SIZE]
            .copy_from_slice(&self.as_ref().to_bytes());
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut buffer = &buf[..];
        Ok(Score {
            value: BlsScalar::from_reader(&mut buffer)?,
            y: BlsScalar::from_reader(&mut buffer)?,
            y_prime: BlsScalar::from_reader(&mut buffer)?,
            r1: BlsScalar::from_reader(&mut buffer)?,
            r2: BlsScalar::from_reader(&mut buffer)?,
        })
    }
}

impl Score {
    /// Returns the value of the [Score](self::Score)
    pub fn value(&self) -> BlsScalar {
        self.value
    }
}

#[cfg(feature = "std")]
pub(self) const SCALAR_FIELD_ORD_DIV_2_POW_128: BlsScalar =
    BlsScalar::from_raw([
        0x3339d80809a1d805,
        0x73eda753299d7d48,
        0x0000000000000000,
        0x0000000000000000,
    ]);

#[cfg(feature = "std")]
pub(self) const MINUS_ONE_MOD_2_POW_128: BlsScalar = BlsScalar::from_raw([
    0xffffffff00000000,
    0x53bda402fffe5bfe,
    0x0000000000000000,
    0x0000000000000000,
]);

#[cfg(feature = "std")]
impl Score {
    /// Given a `Bid`, compute it's Score and return it.
    pub fn compute_score(
        bid: &Bid,
        secret: &JubJubAffine,
        secret_k: BlsScalar,
        bid_tree_root: BlsScalar,
        consensus_round_seed: u64,
        latest_consensus_round: u64,
        latest_consensus_step: u64,
    ) -> Result<Score, BlindBidError> {
        if latest_consensus_round > bid.expiration {
            return Err(BlindBidError::ExpiredBid);
        };

        let consensus_round_seed = BlsScalar::from(consensus_round_seed);
        let latest_consensus_round = BlsScalar::from(latest_consensus_round);
        let latest_consensus_step = BlsScalar::from(latest_consensus_step);

        // Compute `y` where `y = H(secret_k, Merkle_root, consensus_round_seed,
        // latest_consensus_round, latest_consensus_step)`.
        let y = sponge::hash(&[
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        ]);
        let (value, _) = bid.decrypt_data(secret)?;

        // Truncate Y to left 128 bits and interpret the result as 128-bit
        // integer. Keep the right 128 bits as another integer (r1).
        let r1 = BigUint::from_bytes_le(&y.to_bytes()[16..32]);
        let y_prime = BigUint::from_bytes_le(&y.to_bytes()[0..16]);

        // Get the bid value outside of the modular field and treat it as
        // an integer.
        let bid_value = BigUint::from_bytes_le(&value.to_bytes());
        // Compute the final score
        let (f, r2) = match y_prime == BigUint::zero() {
            // If y' != 0 -> f = (bid_value * 2^128 / y')
            // r2 is assigned to the remainder of the division.
            false => {
                let num = bid_value * (BigUint::one() << 128);
                (&num / &y_prime, &num % &y_prime)
            }
            // If y' == 0 -> f = bid_value * 2^128
            // Since there's not any division, r2 is assigned to 0 since
            // there's not any remainder.
            true => (bid_value * (BigUint::one() << 128), BigUint::zero()),
        };

        // Get Scalars from the bigUints and return a `Score` if the conversions
        // could be correctly done.
        Ok(Score {
            value: biguint_to_scalar(f)?,
            y,
            y_prime: biguint_to_scalar(y_prime)?,
            r1: biguint_to_scalar(r1)?,
            r2: biguint_to_scalar(r2)?,
        })
    }

    /// Proves that a `Score` is correctly generated.
    /// Prints the proving statements in the passed Constraint System.
    pub fn prove_correct_score_gadget(
        &self,
        composer: &mut StandardComposer,
        bid_value: AllocatedScalar,
        secret_k: AllocatedScalar,
        bid_tree_root: AllocatedScalar,
        consensus_round_seed: AllocatedScalar,
        latest_consensus_round: AllocatedScalar,
        latest_consensus_step: AllocatedScalar,
    ) -> Variable {
        // Allocate constant one & zero values.
        let one = composer.add_witness_to_circuit_description(BlsScalar::one());
        let zero =
            composer.add_witness_to_circuit_description(BlsScalar::zero());
        // Allocate Score fields needed for the gadget.
        let r1 = AllocatedScalar::allocate(composer, self.r1);
        let r2 = AllocatedScalar::allocate(composer, self.r2);
        let y = AllocatedScalar::allocate(composer, self.y);
        let y_prime = AllocatedScalar::allocate(composer, self.y_prime);
        let score_alloc_scalar =
            AllocatedScalar::allocate(composer, self.value);
        let two_pow_128 = BlsScalar::from(2u64).pow(&[128, 0, 0, 0]);

        // 1. y = H(k||H(Bi)||sigma^s||k^t||k^s)
        let should_be_y = sponge::gadget(
            composer,
            &[
                secret_k.var,
                bid_tree_root.var,
                consensus_round_seed.var,
                latest_consensus_round.var,
                latest_consensus_step.var,
            ],
        );
        // Constrain the result of the hash to be equal to the Score y
        composer.assert_equal(should_be_y, y.var);

        // 2. Y = 2^128 * r1 + Y'
        composer.add_gate(
            y_prime.var,
            r1.var,
            y.var,
            BlsScalar::one(),
            two_pow_128,
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // 3.(r1 < |Fr|/2^128 AND Y' < 2^128) OR (r1 = |Fr|/2^128 AND Y' < |Fr|
        // mod 2^128).
        //
        // 3.1. First op will be a complex rangeproof between r1 and the range
        // (Order of the Scalar Field / 2^128 (No modular division)) The result
        // should be 0 if the rangeproof holds.
        let first_cond =
            max_bound(composer, SCALAR_FIELD_ORD_DIV_2_POW_128, r1).0;

        // 3.2. Then we have a single Rangeproof between Y' being in the range
        // [0-2^128]
        let second_cond = max_bound(composer, two_pow_128, y_prime).0;
        // 3.3. Third, we have an equalty checking between r1 & the order of the
        // Scalar field divided (no modular division) by 2^128.
        // Since the gadget uses an `AllocatedScalar` here, we need to
        // previously constrain it's variable to a constant value: `the
        // order of the Scalar field divided (no modular division) by
        // 2^128` in this case. Then generate the `AllocatedScalar` and
        // call the gadget.
        let scalar_field_ord_div_2_128_variable = composer
            .add_witness_to_circuit_description(SCALAR_FIELD_ORD_DIV_2_POW_128);
        let scalar_field_ord_div_2_128 = AllocatedScalar {
            var: scalar_field_ord_div_2_128_variable,
            scalar: SCALAR_FIELD_ORD_DIV_2_POW_128,
        };
        // Now we can call the gadget with all the constraints applied to ensure
        // that the variable that represents 2^128
        let third_cond = maybe_equal(composer, scalar_field_ord_div_2_128, r1);
        // 3.4. Finally, constraints for y' checking it's between
        // [0, Order of the ScalarField mod 2^128].
        let fourth_cond =
            max_bound(composer, MINUS_ONE_MOD_2_POW_128, y_prime).0;
        // Apply the point 3 constraint.
        //(r1 < |Fr|/2^128 AND Y' < 2^128 +1)
        let left_assign = composer.mul(
            BlsScalar::one(),
            first_cond,
            second_cond,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // (r1 = |Fr|/2^128 AND Y' < |Fr| mod 2^128)
        let right_assign = composer.mul(
            BlsScalar::one(),
            third_cond,
            fourth_cond,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // left_assign XOR right_assign = 1
        // This is possible since condition 1. and 3. are mutually exclusive.
        // That means that if one is true, the other part of the
        // equation will be false (0). Therefore, we can apply a mul
        // gate since the inputs are boolean and both sides of the equal
        // can't be true, but both can be false, and this has to make
        // the proof fail. The following gate computes the XOR and
        // constraints the result to be equal to one.
        composer.add_gate(
            left_assign,
            right_assign,
            one,
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            BlsScalar::zero(),
        );

        // 4. r2 < Y'
        let r2_min_y_prime = composer.add(
            (BlsScalar::one(), r2.var),
            (-BlsScalar::one(), y_prime.var),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let r2_min_y_prime_scalar = r2.scalar - y_prime.scalar;
        let r2_min_y_prime = AllocatedScalar {
            var: r2_min_y_prime,
            scalar: r2_min_y_prime_scalar,
        };

        // One indicates a failure here.
        let should_be_one = max_bound(
            composer,
            BlsScalar::from(2u64).pow(&[128, 0, 0, 0]),
            r2_min_y_prime,
        );

        // Check that the result of the range_proof is indeed 0 to assert it
        // passed.
        composer.constrain_to_constant(
            should_be_one.0,
            BlsScalar::one(),
            BlsScalar::zero(),
        );

        // 5. q < 2^120
        composer.range_gate(score_alloc_scalar.var, 120usize);
        // 5. q*Y' + r2 -d*2^128 = 0
        //
        // f * Y'
        let f_y_prime_prod = composer.mul(
            BlsScalar::one(),
            score_alloc_scalar.var,
            y_prime.var,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // q*Y' + r2
        let left = composer.add(
            (BlsScalar::one(), f_y_prime_prod),
            (BlsScalar::one(), r2.var),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // (q*Y' + r2) - v*2^128 = 0
        composer.add_gate(
            left,
            bid_value.var,
            zero,
            BlsScalar::one(),
            -two_pow_128,
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        score_alloc_scalar.var
    }
}

#[cfg(feature = "std")]
/// Given the y parameter, return the y' and it's inverse value.
fn biguint_to_scalar(biguint: BigUint) -> Result<BlsScalar, BlindBidError> {
    let mut bytes = [0u8; 32];
    let biguint_bytes = biguint.to_bytes_le();
    if biguint_bytes.len() > 32 {
        return Err(BlindBidError::InvalidScoreFieldsLen);
    };
    bytes[..biguint_bytes.len()].copy_from_slice(&biguint_bytes);
    // Due to the previous conditions, we can unwrap here safely.
    Ok(BlsScalar::from_bytes(&bytes).unwrap())
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use dusk_bytes::Serializable;
    use dusk_pki::{PublicSpendKey, SecretSpendKey};
    use dusk_plonk::jubjub::GENERATOR_EXTENDED;
    use rand::Rng;

    fn random_bid(secret: &JubJubScalar) -> Bid {
        let mut rng = rand::thread_rng();

        let secret_k = BlsScalar::random(&mut rng);
        let pk_r = PublicSpendKey::from(SecretSpendKey::random(&mut rng));
        let stealth_addr = pk_r.gen_stealth_address(&secret);
        let secret = GENERATOR_EXTENDED * secret;
        let value: u64 = (&mut rand::thread_rng())
            .gen_range(crate::V_RAW_MIN, crate::V_RAW_MAX);
        let value = JubJubScalar::from(value);
        let eligibility = u64::MAX;
        let expiration = u64::MAX;

        Bid::new(
            &mut rng,
            &stealth_addr,
            &value,
            &secret.into(),
            secret_k,
            eligibility,
            expiration,
        )
        .expect("Bid creation error")
    }

    #[test]
    fn biguint_scalar_conversion() {
        let rand_scalar = BlsScalar::random(&mut rand::thread_rng());
        let big_uint = BigUint::from_bytes_le(&rand_scalar.to_bytes());

        assert_eq!(biguint_to_scalar(big_uint).unwrap(), rand_scalar)
    }

    fn allocate_fields(
        composer: &mut StandardComposer,
        value: JubJubScalar,
        secret_k: BlsScalar,
        bid_tree_root: BlsScalar,
        consensus_round_seed: BlsScalar,
        latest_consensus_round: BlsScalar,
        latest_consensus_step: BlsScalar,
    ) -> (
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
        AllocatedScalar,
    ) {
        let value = AllocatedScalar::allocate(composer, value.into());

        let secret_k = AllocatedScalar::allocate(composer, secret_k);
        let bid_tree_root = AllocatedScalar::allocate(composer, bid_tree_root);
        let consensus_round_seed =
            AllocatedScalar::allocate(composer, consensus_round_seed);
        let latest_consensus_round =
            AllocatedScalar::allocate(composer, latest_consensus_round);
        let latest_consensus_step =
            AllocatedScalar::allocate(composer, latest_consensus_step);
        (
            value,
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )
    }

    #[test]
    fn correct_score_gen_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret);
        let secret = GENERATOR_EXTENDED * &secret;
        let (value, _) =
            bid.decrypt_data(&secret.into()).expect("Decryption error");

        // Generate fields for the Bid & required by the compute_score
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = 3u64;
        // Set latest consensus round as the max value so the score gen does not
        // fail for that but for the proof verification error if that's
        // the case
        let latest_consensus_round = 25519u64;
        let latest_consensus_step = 2u64;

        // Edit score fields which should make the test fail
        let score = Score::compute_score(
            &bid,
            &secret.into(),
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )
        .expect("Score computation error");

        // Proving
        let mut prover = Prover::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            prover.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            BlsScalar::from(consensus_round_seed),
            BlsScalar::from(latest_consensus_round),
            BlsScalar::from(latest_consensus_step),
        );
        score.prove_correct_score_gadget(
            prover.mut_cs(),
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            verifier.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            BlsScalar::from(consensus_round_seed),
            BlsScalar::from(latest_consensus_round),
            BlsScalar::from(latest_consensus_step),
        );
        score.prove_correct_score_gadget(
            verifier.mut_cs(),
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }

    #[test]
    fn incorrect_score_gen_proof() -> Result<()> {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 16)?;

        // Generate a correct Bid
        let secret = JubJubScalar::random(&mut rand::thread_rng());
        let bid = random_bid(&secret);
        let secret = GENERATOR_EXTENDED * &secret;
        let (value, _) =
            bid.decrypt_data(&secret.into()).expect("Decryption Error");

        // Generate fields for the Bid & required by the compute_score
        let secret_k = BlsScalar::random(&mut rand::thread_rng());
        let bid_tree_root = BlsScalar::random(&mut rand::thread_rng());
        let consensus_round_seed = 5u64;
        // Set the timestamps to the maximum possible value so the generation of
        // the score does not fail for that reason but for the proof
        // verification.
        let latest_consensus_round = 25519u64;
        let latest_consensus_step = 2u64;

        // Edit score fields which should make the test fail
        let mut score = Score::compute_score(
            &bid,
            &secret.into(),
            secret_k,
            bid_tree_root,
            consensus_round_seed,
            latest_consensus_round,
            latest_consensus_step,
        )
        .expect("Score Computation error");
        score.value = BlsScalar::from(5686536568u64);
        score.r1 = BlsScalar::from(5898956968u64);

        // Proving
        let mut prover = Prover::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            prover.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            BlsScalar::from(consensus_round_seed),
            BlsScalar::from(latest_consensus_round),
            BlsScalar::from(latest_consensus_step),
        );
        score.prove_correct_score_gadget(
            prover.mut_cs(),
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"testing");
        // Allocate values
        let (
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        ) = allocate_fields(
            verifier.mut_cs(),
            value,
            secret_k,
            bid_tree_root,
            BlsScalar::from(consensus_round_seed),
            BlsScalar::from(latest_consensus_round),
            BlsScalar::from(latest_consensus_step),
        );
        score.prove_correct_score_gadget(
            verifier.mut_cs(),
            alloc_value,
            alloc_secret_k,
            alloc_bid_tree_root,
            alloc_consensus_round_seed,
            alloc_latest_consensus_round,
            alloc_latest_consensus_step,
        );
        verifier.preprocess(&ck)?;
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_err());

        Ok(())
    }
}

#[cfg(test)]
mod score_serialization {
    use super::*;

    #[test]
    fn score_serialization_roundtrip() {
        let score = Score {
            value: BlsScalar::one(),
            y: BlsScalar::one(),
            y_prime: BlsScalar::one(),
            r1: BlsScalar::one(),
            r2: BlsScalar::one(),
        };

        let score_bytes = score.to_bytes();
        let score_from_bytes =
            Score::from_bytes(&score_bytes).expect("Invalid roundtrip");
        assert_eq!(score, score_from_bytes)
    }
}
