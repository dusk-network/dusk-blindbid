// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Score generation module
pub(crate) mod errors;
pub mod score;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
pub use score::Score;
pub(crate) use score::{compute_score, prove_correct_score_gadget};

pub(crate) const SCALAR_FIELD_ORD_DIV_2_POW_128: BlsScalar =
    BlsScalar::from_raw([
        0x3339d80809a1d805,
        0x73eda753299d7d48,
        0x0000000000000000,
        0x0000000000000000,
    ]);

pub(crate) const MINUS_ONE_MOD_2_POW_128: BlsScalar = BlsScalar::from_raw([
    0xffffffff00000000,
    0x53bda402fffe5bfe,
    0x0000000000000000,
    0x0000000000000000,
]);
