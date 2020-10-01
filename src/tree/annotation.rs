use super::StorageScalar;
use crate::bid::Bid;

use kelvin::annotations::{Associative, Cardinality};
use kelvin::{annotation, Blake2b, Content, Sink, Source};
use poseidon252::StorageScalar as PoseidonStorageScalar;
use std::borrow::Borrow;
use std::cmp;
use std::io;

annotation! {
    pub struct BidAnnotation {
        poseidon_hash: StorageScalar,
        block_height: BidHeightRange,
        count: Cardinality<u64>,
    }
}

impl BidAnnotation {
    pub fn poseidon_hash(&self) -> &StorageScalar {
        &self.poseidon_hash
    }

    pub fn block_height(&self) -> &BidHeightRange {
        &self.block_height
    }

    pub fn count(&self) -> &Cardinality<u64> {
        &self.count
    }
}

impl Borrow<PoseidonStorageScalar> for BidAnnotation {
    fn borrow(&self) -> &PoseidonStorageScalar {
        self.poseidon_hash.borrow()
    }
}

#[derive(Default, Debug, Clone)]
pub struct BidHeightRange {
    pub eligibility: StorageScalar,
    pub expiration: StorageScalar,
}

impl Associative for BidHeightRange {
    fn op(&mut self, other: &Self) {
        self.eligibility = cmp::min(self.eligibility, other.eligibility);
        self.expiration = cmp::max(self.expiration, other.expiration);
    }
}

impl<'a> From<&'a Bid> for BidHeightRange {
    fn from(bid: &'a Bid) -> Self {
        Self {
            eligibility: bid.eligibility.into(),
            expiration: bid.expiration.into(),
        }
    }
}

impl Content<Blake2b> for BidHeightRange {
    fn persist(&mut self, sink: &mut Sink<Blake2b>) -> io::Result<()> {
        self.eligibility.persist(sink)?;
        self.expiration.persist(sink)?;

        Ok(())
    }

    fn restore(source: &mut Source<Blake2b>) -> io::Result<Self> {
        let eligibility = StorageScalar::restore(source)?;
        let expiration = StorageScalar::restore(source)?;

        Ok(Self {
            eligibility,
            expiration,
        })
    }
}
