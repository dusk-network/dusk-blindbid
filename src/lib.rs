// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! ![GitHub branch checks state](https://img.shields.io/github/checks-status/dusk-network/dusk-blindbid/master)
//! ![GitHub](https://img.shields.io/github/license/dusk-network/dusk-blindbid)
//! ![Crates.io](https://img.shields.io/crates/v/dusk-blindbid)
//!
//! In order to participate in the SBA consensus, Block generators have to
//! submit a bid in DUSK. As long as their bid is active - and their full-node
//! is connected with the internet and running- they are participating in the
//! consensus rounds. Essentially, every time a consensus round is run, the
//! Block Generator software generates a comprehensive zero-knowledge proof, and
//! executes various steps in order to generate a valid candidate block, and
//! compete with the other Block Generators for a chance to become the winner of
//! the consensus round.
//!
//! ![](https://public.bnbstatic.com/static/research/static/images/projects/dusk-network/image18.png)
//!
//! Below we describe the three main processes that happen
//! every consensus round. Please note that 1 and 2 are run as part of the same
//! algorithm.
//!
//! ## 1: Score generation.
//! Block Generators obtain a score from a lottery by executing the Score
//! Generation Function. The score is positively influenced by the amount of
//! DUSK that the Block Generator bids. In other words, the higher the bid, the
//! better the chance to generate a high score. This is important to guarantee
//! _Sybil attack_ protection.
//!
//! Without this link a bad actor could subvert the reputation system by
//! creating multiple identities. Also note: there are _minimum_ and _maximum_
//! thresholds that determine the minimum and maximum size of the bid.
//!
//! ## 2. Proof of Blind-Bid Generation.
//!
//! In general computing science, a circuit is a computational model through
//! which input values proceed through a sequence of gates, each of which
//! computes a specific function. In our case, the circuits perform the logical
//! checks with public and private inputs to make sure that the generated Blind
//! Bid proofs are generated by the rules of the game. For explanatory reasons,
//! we define two circuits although in practice, these two are a collection of
//! gadgets added up together in order to compose the [`BlindBidCircuit`]:
//!
//! 1. Blind Bid circuit;
//! 2. Score Generation circuit.
//!
//! Below we describe the Blind Bid circuit and the score generation circuit,
//! who together form the pillars of the Proof-of-Blind Bid procedure.
//!
//! ### Blind Bid Circuit
//! ![Fig1](https://lh4.googleusercontent.com/oPR_7LLAAj6K8qjxiqMMavfucdslgv3DAGcElrn6hwDLMk0mYucfcwPyqLoT0HIyqvqmUDof4PhnXFV6-3tbImYtdG4WNHJcq72GaLsHHKE4EMiIv8pMJqLplGVlzuK6nIYsUp_r)
//! Some noteworthy proofs are:
//!
//! Opening Proof: this is generated to check where the Bid has been stored on
//! the merkle-tree (you could see this as a ledger where values are stored)
//! that contains all of the bids. This proof checks that the Bid has indeed
//! been made, and can be trusted.
//!
//! Pre-image check of the Bid: this is a consistency check that aims to make it
//! impossible to cheat during the computation of the bid. If a bad actor
//! attempts to cheat, the opening proof will not be the same and therefore not
//! consistent.
//!
//! It goes both ways. If you try to cheat on the pre-image check, the Opening
//! Proof will fail as a result. And if you try to cheat on the Opening Proof,
//! the pre-image would be impossible to compute because there are 2^256
//! different possibilities. To put that in perspective, even with all the time
//! in the universe, you would not be able to check all of them (note that a
//! consensus round also only takes ~10 seconds).
//!
//! In Fig 1. you can see that in step 3. & 4 we perform range checks to make
//! sure that the Bid is valid and eligible during the current consensus round
//! and steps. Finally, in proofs 7. & 8. we check the hash of the secret (H(k))
//! and the prover ID (i), asking for proof that the block generator - who we
//! assume has posted the bid -, indeed is the owner of the bid.
//!
//! Once the process above has been completed we move to Score Generation.
//!
//! ### Score Generation Circuit
//! ![Fig2](https://lh5.googleusercontent.com/I6b88LUtOM5MIcbkJu3p0CZdoz34kBl7PXFovQbt4uiuAExOyW0yfLsI-1BbnzOh0u_kDv5LOB0ztuJgrh7h3y2Qh94qNN4FnP6P2Yi0cxHjJhWC3sSA49jEZtYLSutXIDkwC4Dz)
//! Score generation needs to be understood as a continuation of the next
//! circuit instead of a different entity.
//!
//! The final step is to check if the Score in the Blind Bid is correct. This
//! step is important, as the Score determines the winner of an election round.
//!
//! The prover ID (y) is directly connected to the secret (k) and pre-image hash
//! of the Bid (H(bidi)), meaning that any changes to the score will
//! automatically result in a different prover ID, and thus a failed constraint
//! on line 1. of the Score Generation Circuit.
//!
//! ## 3. Propagation.
//! During each consensus round, the Block Generator checks
//! the score that he produced, and verifies whether it is greater than the
//! _**minimum score threshold**_. If it is indeed greater, then the Block
//! Generator generates the aforementioned proofs and propagates the score
//! obtained, the zero-knowledge proof computed and various other elements
//! alongside the Block Candidate to his peers in the network. The Block
//! Generator that computed the highest score is considered to be the leader of
//! the current iteration of the consensus.

#![allow(non_snake_case)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://lh3.googleusercontent.com/SmwswGxtgIANTbDrCOn5EKcRBnVdHjmYsHYxLq2HZNXWCQ9-fZyaea-bNgdX9eR0XGSqiMFi=w128-h128-e365",
    html_favicon_url = "https://dusk.network/lib/img/favicon-16x16.png",
    html_root_url = "https://docs.rs/dusk-blindbid/0.0.0"
)]

pub(crate) mod bid;
pub(crate) mod errors;
#[cfg(feature = "std")]
pub(crate) mod proof;
pub use bid::{Bid, Score};
pub use errors::BlindBidError;
#[cfg(all(feature = "std", feature = "canon"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "canon", feature = "std"))))]
pub use proof::BlindBidCircuit;
/// The minimum amount user is permitted to bid.
pub const V_RAW_MIN: u64 = 50_000u64;
/// The maximum amount user is permitted to bid.
pub const V_RAW_MAX: u64 = 250_000u64;

use dusk_jubjub::JubJubScalar;
pub(crate) const V_MIN: JubJubScalar =
    JubJubScalar::from_raw([V_RAW_MIN, 0, 0, 0]);
pub(crate) const V_MAX: JubJubScalar =
    JubJubScalar::from_raw([V_RAW_MAX, 0, 0, 0]);
