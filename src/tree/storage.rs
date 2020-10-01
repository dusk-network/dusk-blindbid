use crate::bid::Bid;
use dusk_plonk::prelude::*;
use kelvin::{Blake2b, Combine, Content, ErasedAnnotation, Sink, Source};
use poseidon252::merkle_lvl_hash::hash;
use poseidon252::{StorageScalar as PoseidonStorageScalar, ARITY};
use std::borrow::Borrow;
use std::io;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageScalar(PoseidonStorageScalar);

impl StorageScalar {
    pub fn s(&self) -> &BlsScalar {
        &(&self.0).0
    }

    pub fn s_mut(&mut self) -> &mut BlsScalar {
        &mut (&mut self.0).0
    }
}

impl<'a> From<&'a Bid> for StorageScalar {
    fn from(bid: &'a Bid) -> StorageScalar {
        bid.hash().into()
    }
}

impl From<&PoseidonStorageScalar> for StorageScalar {
    fn from(s: &PoseidonStorageScalar) -> Self {
        StorageScalar(*s)
    }
}

impl From<PoseidonStorageScalar> for StorageScalar {
    fn from(s: PoseidonStorageScalar) -> Self {
        StorageScalar(s)
    }
}

impl From<&BlsScalar> for StorageScalar {
    fn from(s: &BlsScalar) -> Self {
        StorageScalar::from(PoseidonStorageScalar(*s))
    }
}

impl From<BlsScalar> for StorageScalar {
    fn from(s: BlsScalar) -> Self {
        StorageScalar::from(PoseidonStorageScalar(s))
    }
}

impl Into<BlsScalar> for &StorageScalar {
    fn into(self) -> BlsScalar {
        *self.borrow()
    }
}

impl Into<BlsScalar> for StorageScalar {
    fn into(self) -> BlsScalar {
        *self.borrow()
    }
}

impl Borrow<BlsScalar> for StorageScalar {
    fn borrow(&self) -> &BlsScalar {
        self.0.borrow()
    }
}

impl Borrow<PoseidonStorageScalar> for StorageScalar {
    fn borrow(&self) -> &PoseidonStorageScalar {
        &self.0
    }
}

impl Content<Blake2b> for StorageScalar {
    fn persist(&mut self, sink: &mut Sink<Blake2b>) -> io::Result<()> {
        self.0.persist(sink)
    }

    fn restore(source: &mut Source<Blake2b>) -> io::Result<Self> {
        PoseidonStorageScalar::restore(source).map(|s| s.into())
    }
}

impl<A> Combine<A> for StorageScalar {
    fn combine<E>(elements: &[E]) -> Option<Self>
    where
        A: Borrow<Self> + Clone,
        E: ErasedAnnotation<A>,
    {
        let mut leaves: [Option<BlsScalar>; ARITY] = [None; ARITY];

        elements
            .iter()
            .zip(leaves.iter_mut())
            .for_each(|(element, leave)| {
                match element.annotation() {
                    Some(annotation) => {
                        let s: &StorageScalar = (*annotation).borrow();
                        *leave = Some(s.into());
                    }
                    None => *leave = None,
                };
            });

        let res = hash::merkle_level_hash(&leaves);
        Some(res.into())
    }
}
