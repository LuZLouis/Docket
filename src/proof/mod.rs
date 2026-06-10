//! Proof-system modules.
//!
//! Round 2 implements the real Algorithm 2 submission-binding proof. Round 5
//! adds the signed range predicate wrapper and test-only mock backend. Round 6
//! adds a feature-gated Bulletproofs range backend. Round 7 adds the L2 proof
//! skeleton and connects its bound check to the range backend abstraction.

pub mod l2;
pub mod range;
pub mod submit;
