// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the Score Generation

use thiserror::Error;

/// Definition of the erros that Bid operations might have.
#[derive(Error, Debug)]
pub enum ScoreError {
    /// Error for the cases when we the score results are too large to
    /// fit inside a `Scalar`.
    #[error("score results do not fit inside of Scalar")]
    InvalidScoreFieldsLen,
    /// Error that happens when you try to generate a `Score` for a `Bid`
    /// has already expired.
    #[error("the bid has already expired")]
    ExpiredBid,
}
