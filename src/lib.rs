// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! BlindBid impl

pub mod bid;
pub mod proof;
pub mod score_gen;

use dusk_plonk::prelude::*;

pub(crate) const V_RAW_MIN: u64 = 50_000u64;
pub(crate) const V_RAW_MAX: u64 = 250_000u64;

/// The minimum amount user is permitted to bid
pub const V_MIN: &'static JubJubScalar =
    &JubJubScalar::from_raw([V_RAW_MIN, 0, 0, 0]);
/// The maximum amount user is permitted to bid
pub const V_MAX: &'static JubJubScalar =
    &JubJubScalar::from_raw([V_RAW_MAX, 0, 0, 0]);
