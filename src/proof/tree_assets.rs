// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use crate::Bid;
use canonical::{Canon, Store};
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_poseidon::tree::{
    PoseidonBranch, PoseidonLeaf, PoseidonMaxAnnotation, PoseidonTree,
};

#[derive(Debug, Clone, Copy, Canon)]
pub struct BidLeaf(pub(crate) Bid);

impl BidLeaf {
    /// Generates a new BidLeaf instance from a `Bid`.
    pub fn new(bid: Bid) -> Self {
        BidLeaf(bid)
    }

    /// Returns the internal bid representation of the `BidLeaf` as with
    /// the `Bid` type.
    pub fn bid(&self) -> Bid {
        self.0
    }

    /// Returns a &mut to the internal bid representation of the `BidLeaf`
    /// as with the `Bid` type.
    pub fn bid_mut(&mut self) -> &mut Bid {
        &mut self.0
    }
}

impl Borrow<u64> for BidLeaf {
    fn borrow(&self) -> &u64 {
        self.0.borrow()
    }
}

impl From<Bid> for BidLeaf {
    fn from(bid: Bid) -> BidLeaf {
        BidLeaf(bid)
    }
}

impl From<BidLeaf> for Bid {
    fn from(leaf: BidLeaf) -> Bid {
        leaf.0
    }
}

impl<S> PoseidonLeaf<S> for BidLeaf
where
    S: Store,
{
    fn poseidon_hash(&self) -> BlsScalar {
        self.0.hash()
    }

    fn pos(&self) -> u64 {
        *self.0.pos()
    }

    fn set_pos(&mut self, pos: u64) {
        self.0.set_pos(pos);
    }
}

pub struct BidTree<S: Store>(
    PoseidonTree<BidLeaf, PoseidonMaxAnnotation, S, 17usize>,
);

impl<S> BidTree<S>
where
    S: Store,
{
    /// Constructor
    pub fn new() -> Self {
        Self(PoseidonTree::new())
    }

    /// Get a bid from a provided index
    #[allow(dead_code)]
    pub fn get(&self, idx: u64) -> Option<BidLeaf> {
        self.0.get(idx as usize).unwrap()
    }

    /// Append a bid to the tree and return its index
    ///
    /// The index will be the last available position
    pub fn push(&mut self, bid: BidLeaf) -> usize {
        self.0.push(bid).unwrap()
    }

    /// Returns a poseidon branch pointing at the specific index
    pub fn poseidon_branch(
        &self,
        idx: usize,
    ) -> Option<PoseidonBranch<17usize>> {
        self.0.branch(idx).unwrap()
    }
}
