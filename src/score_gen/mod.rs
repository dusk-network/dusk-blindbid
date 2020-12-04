// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Score generation module
pub(crate) mod score;
#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Score {
    pub score: BlsScalar,
    pub(crate) y: BlsScalar,
    pub(crate) y_prime: BlsScalar,
    pub(crate) r1: BlsScalar,
    pub(crate) r2: BlsScalar,
}

impl Score {
    pub(crate) fn new(
        score: BlsScalar,
        y: BlsScalar,
        y_prime: BlsScalar,
        r1: BlsScalar,
        r2: BlsScalar,
    ) -> Self {
        Score {
            score,
            y,
            y_prime,
            r1,
            r2,
        }
    }
}
