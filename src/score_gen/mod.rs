// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Score generation module
pub mod score;
use dusk_bls12_381::BlsScalar;
pub use score::Score;

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
