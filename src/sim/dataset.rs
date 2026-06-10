use crate::{AvsaError, Result};
use rand::Rng;

/// Manuscript-scale simulated dimensions for later benchmark rounds.
pub const MANUSCRIPT_SIM_DIMS: &[usize] = &[19_000, 62_000, 273_000, 818_000];

/// Sample a signed update vector with each coordinate in [-B_inf, B_inf].
pub fn sample_signed_update<R: Rng + ?Sized>(
    dim: usize,
    b_inf: i64,
    rng: &mut R,
) -> Result<Vec<i64>> {
    if b_inf < 0 {
        return Err(AvsaError::InvalidBound("b_inf must be nonnegative".into()));
    }
    Ok((0..dim).map(|_| rng.gen_range(-b_inf..=b_inf)).collect())
}
