use super::{BidTreeInner, StorageScalar};
use kelvin::{Blake2b, Compound, HandleType, Method, SearchResult};

pub struct BlockHeightFilter {
    pub block_height: StorageScalar,
}

impl BlockHeightFilter {
    pub fn new(block_height: StorageScalar) -> Self {
        Self { block_height }
    }
}

impl Method<BidTreeInner, Blake2b> for BlockHeightFilter {
    fn select(
        &mut self,
        compound: &BidTreeInner,
        offset: usize,
    ) -> SearchResult {
        let c = compound.children();

        for (i, h) in c.iter().enumerate() {
            if i >= offset {
                if let Some(a) = h.annotation() {
                    if self.block_height <= a.block_height().expiration {
                        match h.handle_type() {
                            HandleType::Leaf => {
                                return SearchResult::Leaf(i - offset)
                            }
                            HandleType::Node => {
                                return SearchResult::Path(i - offset)
                            }
                            HandleType::None => return SearchResult::None,
                        }
                    }
                }
            }
        }

        SearchResult::None
    }
}
