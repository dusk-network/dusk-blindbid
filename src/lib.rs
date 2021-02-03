// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! BlindBid impl
#![allow(non_snake_case)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod bid;
pub mod errors;
#[cfg(feature = "std")]
pub mod proof;
#[cfg(all(feature = "std", feature = "canon"))]
pub use proof::BlindBidCircuit;

pub const V_RAW_MIN: u64 = 50_000u64;
pub const V_RAW_MAX: u64 = 250_000u64;

use dusk_jubjub::JubJubScalar;
/// The minimum amount user is permitted to bid
pub const V_MIN: JubJubScalar = JubJubScalar::from_raw([V_RAW_MIN, 0, 0, 0]);
/// The maximum amount user is permitted to bid
pub const V_MAX: JubJubScalar = JubJubScalar::from_raw([V_RAW_MAX, 0, 0, 0]);
