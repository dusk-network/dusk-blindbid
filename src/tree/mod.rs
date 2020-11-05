use crate::bid::Bid;
use anyhow::Result;
use canonical::Store;
use poseidon252::tree::{
    PoseidonBranch, PoseidonMaxAnnotation, PoseidonTree, PoseidonTreeIterator,
};

pub const DEPTH: usize = 17;

#[derive(Debug, Clone)]
pub struct BidTree<S>
where
    S: Store,
{
    inner: PoseidonTree<Bid, PoseidonMaxAnnotation, S, DEPTH>,
}

impl<S> BidTree<S>
where
    S: Store,
{
    pub fn new() -> Self {
        let inner = PoseidonTree::new();

        Self { inner }
    }

    pub fn push(&mut self, bid: Bid) -> Result<usize> {
        self.inner.push(bid)
    }

    pub fn get(&mut self, n: usize) -> Result<Option<Bid>> {
        self.inner.get(n)
    }

    pub fn branch(&self, n: usize) -> Result<Option<PoseidonBranch<DEPTH>>> {
        self.inner.branch(n)
    }

    pub fn iter_block_height(
        &self,
        block_height: u64,
    ) -> Result<PoseidonTreeIterator<Bid, PoseidonMaxAnnotation, S, u64, DEPTH>>
    {
        self.inner.iter_walk(block_height)
    }
}
