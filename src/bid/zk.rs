use super::bid::TYPE_FIELDS;
use crate::bid::Bid;
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;
use poseidon252::cipher::CIPHER_SIZE;
use poseidon252::sponge::sponge::sponge_hash_gadget;

#[derive(Debug, Clone, Copy)]
pub struct ZkBid {
    /// b_enc (encrypted value and blinder)
    pub encrypted_data: [Variable; CIPHER_SIZE],
    /// Nonce used by the cypher
    pub nonce: Variable,
    /// Stealth address of the bidder
    pub stealth_address_pk_r: Point,
    pub stealth_address_r: Point,
    /// m
    pub hashed_secret: Variable,
    /// c (Pedersen Commitment)
    pub c: Point,
    /// Elegibility timestamp
    pub eligibility: Variable,
    /// Expiration timestamp
    pub expiration: Variable,
    /// Position in the merkle tree
    pub pos: Variable,
}

impl ZkBid {
    pub fn new(composer: &mut StandardComposer, bid: &Bid) -> Self {
        let zero =
            composer.add_witness_to_circuit_description(BlsScalar::zero());

        let mut encrypted_data = [zero; CIPHER_SIZE];
        bid.encrypted_data
            .cipher()
            .iter()
            .zip(encrypted_data.iter_mut())
            .for_each(|(c, d)| {
                *d = composer.add_input(*c);
            });

        let nonce = composer.add_input(bid.nonce);

        let stealth_address_pk_r = Point::from_private_affine(
            composer,
            bid.stealth_address.pk_r().into(),
        );

        let stealth_address_r = Point::from_private_affine(
            composer,
            bid.stealth_address.R().into(),
        );

        let hashed_secret = composer.add_input(bid.hashed_secret);

        let c = Point::from_private_affine(composer, bid.c.into());

        let eligibility = composer.add_input(BlsScalar::from(bid.eligibility));
        let expiration = composer.add_input(BlsScalar::from(bid.expiration));
        let pos = composer.add_input(BlsScalar::from(bid.pos));

        Self {
            encrypted_data,
            nonce,
            stealth_address_r,
            stealth_address_pk_r,
            hashed_secret,
            c,
            eligibility,
            expiration,
            pos,
        }
    }

    pub fn preimage(&self, composer: &mut StandardComposer) -> Variable {
        let mut words_deposit = Vec::with_capacity(11);

        // Safe unwrap
        let type_fields = BlsScalar::from_bytes(&TYPE_FIELDS).unwrap();
        words_deposit.push(composer.add_input(type_fields));

        words_deposit.extend_from_slice(&self.encrypted_data);

        words_deposit.push(*self.stealth_address_pk_r.x());
        words_deposit.push(*self.stealth_address_pk_r.y());

        words_deposit.push(*self.stealth_address_r.x());
        words_deposit.push(*self.stealth_address_r.y());

        words_deposit.push(self.hashed_secret);

        words_deposit.push(*self.c.x());
        words_deposit.push(*self.c.y());

        words_deposit.push(self.eligibility);
        words_deposit.push(self.expiration);
        words_deposit.push(self.pos);

        sponge_hash_gadget(composer, words_deposit.as_slice())
    }
}
