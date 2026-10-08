//! Docket: accountable and verifiable secure aggregation.
//!
//! This crate contains the current security protocol and its local evaluation
//! harness. It does not include the historical estimator or pairwise-mask
//! prototype from the development repository.
pub mod crypto;
pub mod harness;
pub mod protocol;

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
pub type Hash = [u8; 32];
pub type Result<T> = std::result::Result<T, String>;
pub fn wire<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(v)
        .expect("serialize typed object")
}
pub fn parse<T: DeserializeOwned>(v: &[u8]) -> Result<T> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1024 * 1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(v)
        .map_err(|e| format!("encoding: {e}"))
}
pub fn hash<T: Serialize>(v: &T) -> Hash {
    Sha256::digest(wire(v)).into()
}
pub fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
