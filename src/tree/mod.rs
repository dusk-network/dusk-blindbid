// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::bid::Bid;
use kelvin::{Blake2b, Branch, Compound, Method};
use nstack::NStack;
use poseidon252::{PoseidonBranch, PoseidonTree};
use std::{io, mem};

pub use annotation::BidAnnotation;
pub use search::BlockHeightFilter;
pub use storage::StorageScalar;

pub mod annotation;
pub mod search;
pub mod storage;

pub type BidTreeInner = NStack<Bid, BidAnnotation, Blake2b>;

pub struct BidTree {
    tree: PoseidonTree<Bid, BidAnnotation, Blake2b>,
}

impl BidTree {
    /// Constructor
    pub fn new(depth: usize) -> Self {
        let tree = PoseidonTree::new(depth);

        Self { tree }
    }

    /// Reference to the internal poseidon tree
    ///
    /// We don't have a mutable reference available because all its mutation
    /// should be protected by encapsulation
    pub fn inner(&self) -> &PoseidonTree<Bid, BidAnnotation, Blake2b> {
        &self.tree
    }

    /// Get a bid from a provided index
    pub fn get(&self, idx: u64) -> io::Result<Option<Bid>> {
        self.tree.get(idx).map(|b| b.map(|b| *b))
    }

    /// Replace the bid of a provided index
    ///
    /// An error is returned if no bid is found
    pub fn replace(&mut self, idx: u64, bid: Bid) -> io::Result<Bid> {
        self.tree
            .get_mut(idx)
            .and_then(|b| {
                b.ok_or(io::Error::new(
                    io::ErrorKind::NotFound,
                    "The bid was not found!",
                ))
            })
            .map(|mut b| mem::replace(&mut *b, bid))
    }

    /// Append a bid to the tree and return its index
    ///
    /// The index will be the last available position
    pub fn push(&mut self, bid: Bid) -> io::Result<u64> {
        self.tree.push(bid)
    }

    /// Returns a poseidon branch pointing at the specific index
    pub fn poseidon_branch(
        &self,
        idx: u64,
    ) -> io::Result<Option<PoseidonBranch>> {
        self.tree.poseidon_branch(idx)
    }

    /// Iterate through the bids of the tree using the provided filter
    pub fn iter_filtered<M: Method<BidTreeInner, Blake2b>>(
        &self,
        filter: M,
    ) -> io::Result<BidTreeIterator<M>> {
        BidTreeIterator::new(&self, filter)
    }

    /// Iterate through the bids from a provided block height
    pub fn iter_at_height<S: Into<StorageScalar>>(
        &self,
        block_height: S,
    ) -> io::Result<BidTreeIterator<BlockHeightFilter>> {
        self.iter_filtered(BlockHeightFilter::new(block_height.into()))
    }
}

pub struct BidTreeIterator<'a, M: Method<BidTreeInner, Blake2b>> {
    filter: M,
    branch: Option<Branch<'a, BidTreeInner, Blake2b>>,
}

impl<'a, M: Method<BidTreeInner, Blake2b>> BidTreeIterator<'a, M> {
    pub fn new(tree: &'a BidTree, mut filter: M) -> io::Result<Self> {
        tree.inner()
            .inner()
            .search(&mut filter)
            .map(|branch| Self { filter, branch })
    }
}

impl<'a, M: Method<BidTreeInner, Blake2b>> Iterator for BidTreeIterator<'a, M> {
    type Item = io::Result<Bid>;

    fn next(&mut self) -> Option<Self::Item> {
        let bid = match &self.branch {
            Some(branch) => **branch,
            None => return None,
        };

        let branch = match self.branch.take() {
            Some(b) => b,
            None => {
                return Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unexpected null!",
                )))
            }
        };

        self.branch = match branch.search(&mut self.filter) {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(bid))
    }
}

#[cfg(test)]
mod tests {
    use crate::bid::Bid;
    use crate::tree::BidTree;
    use crate::{V_RAW_MAX, V_RAW_MIN};
    use dusk_pki::SecretSpendKey;
    use dusk_plonk::jubjub::{AffinePoint, GENERATOR_EXTENDED};
    use dusk_plonk::prelude::*;
    use rand::rngs::StdRng;
    use rand::{CryptoRng, Rng, SeedableRng};
    use std::cmp;

    #[derive(Debug, Clone, Copy)]
    pub struct BidContainer {
        pub bid: Bid,
        pub k: BlsScalar,
        pub sk: SecretSpendKey,
        pub encrypt_secret: AffinePoint,
        pub idx: u64,
    }

    impl BidContainer {
        /// Constructor
        pub fn new(
            bid: Bid,
            k: BlsScalar,
            sk: SecretSpendKey,
            encrypt_secret: AffinePoint,
            idx: u64,
        ) -> Self {
            Self {
                bid,
                k,
                sk,
                encrypt_secret,
                idx,
            }
        }

        /// Set the tree index
        pub fn set_idx(&mut self, idx: u64) {
            self.idx = idx;
        }

        /// Create a random bid with all the underlying data except for the tree
        /// index
        pub fn random<R>(rng: &mut R) -> BidContainer
        where
            R: Rng + CryptoRng,
        {
            let k = BlsScalar::random(rng);

            let sk = SecretSpendKey::random(rng);
            let pk = sk.public_key();

            let pk_r = pk.gen_stealth_address(&JubJubScalar::random(rng));

            let encrypt_secret = JubJubScalar::random(rng);
            let encrypt_secret: AffinePoint =
                (GENERATOR_EXTENDED * encrypt_secret).into();

            let value: u64 =
                (&mut rand::thread_rng()).gen_range(V_RAW_MIN, V_RAW_MAX);
            let value = JubJubScalar::from(value);

            let a = BlsScalar::random(rng);
            let b = BlsScalar::random(rng);

            let elegibility = cmp::min(a, b);
            let expiration = cmp::max(a, b);

            let bid = Bid::new(
                rng,
                &pk_r,
                &value,
                &encrypt_secret,
                k,
                elegibility,
                expiration,
            )
            .expect("Error generating bid!");

            BidContainer::new(bid, k, sk, encrypt_secret, 0)
        }
    }

    #[test]
    fn block_height_search() {
        let mut tree = BidTree::new(17);
        let mut rng_seed = StdRng::seed_from_u64(437894u64);
        let rng = &mut rng_seed;

        // Create 250 random bids and append them to the tree
        let bids: Vec<BidContainer> = (0..250)
            .map(|_| {
                let mut b = BidContainer::random(rng);

                tree.push(b.bid)
                    .map(|idx| b.set_idx(idx))
                    .expect("Failed to append bid to the tree!");

                b
            })
            .collect();

        // Perform the search on every bid
        bids.iter().for_each(|b| {
            let block_height = b.bid.eligibility;
            let view_key = b.sk.view_key();

            let results: Vec<Bid> = tree.iter_at_height(block_height).unwrap().filter_map(|b| {
                let b = b.unwrap();

                if b.expiration < block_height {
                    panic!("An expired bid was returned");
                }

                if view_key.owns(&b) {
                    Some(b)
                } else {
                    None
                }
            }).collect();

            // The target bid should be returned
            if !results.iter().any(|r| r == &b.bid) {
                panic!(
                    "Search failed for bid {} with expiration {:?} and filter {:?} with criteria {:?}",
                    b.idx,
                    b.bid.expiration,
                    block_height,
                    block_height <= b.bid.expiration,
                );
            }
        });
    }
}
