//! Round 1 AVSA reference implementation skeleton.
//!
//! The implemented layer is intentionally narrow: parameters, signed-update
//! simulation, scalar vectors, Pedersen commitments, complete pairwise masks,
//! mask tags, client-record hashing, submission binding, deterministic
//! transcript roots, and decision/appeal audit skeletons.

pub mod audit;
pub mod bench;
pub mod commit;
pub mod error;
pub mod mask;
pub mod params;
pub mod proof;
pub mod receipt;
pub mod record;
pub mod sim;
pub mod transcript;
pub mod vector;

pub use error::{AvsaError, Result};

/// Public client identifier used throughout the reference implementation.
pub type ClientId = u64;
