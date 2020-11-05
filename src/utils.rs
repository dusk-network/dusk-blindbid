use anyhow::{anyhow, Result};
use dusk_plonk::jubjub::AffinePoint;
use dusk_plonk::prelude::*;

pub fn read_scalar(s: &[u8; 32]) -> Result<BlsScalar> {
    let s: Option<BlsScalar> = BlsScalar::from_bytes(s).into();
    s.ok_or(anyhow!("Error converting scalar from the provided bytes"))
}

pub fn read_jubjub_affine(p: [u8; 32]) -> Result<AffinePoint> {
    let p: Option<AffinePoint> = AffinePoint::from_bytes(p).into();
    p.ok_or(anyhow!(
        "Error converting affine point from the provided bytes"
    ))
}
