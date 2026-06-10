//! Benchmark and CSV reporting helpers.
//!
//! This module is intentionally outside the trusted protocol path. It reuses
//! the protocol APIs and adds only deterministic case generation, timing,
//! benchmark-only serialization, and CSV writing.

pub mod cases;
pub mod formal;
pub mod runner;
