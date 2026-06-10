use crate::{AvsaError, Result};

/// Round 1 host-side no-wraparound bound.
///
/// The curve25519 scalar modulus is about 2^252 and is not exposed as a simple
/// host integer by `curve25519-dalek`. Round 1 therefore uses this deliberately
/// conservative host-side value in tests and simulations. Parameters accepted
/// by this check are safely below q/2, but some cryptographically valid large
/// parameters may be rejected until a later round adds a dedicated modulus
/// comparison helper.
pub const ROUND1_HOST_NO_WRAP_Q_HALF: i128 = 1_i128 << 120;

/// Public AVSA round parameters needed by the algebraic layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvsaParams {
    pub dim: usize,
    pub n_selected: usize,
    pub n_max_admitted: usize,
    pub b_inf: i64,
    pub b2_sq: i128,
}

impl AvsaParams {
    /// Construct and validate AVSA parameters.
    pub fn new(
        dim: usize,
        n_selected: usize,
        n_max_admitted: usize,
        b_inf: i64,
        b2_sq: i128,
    ) -> Result<Self> {
        let params = Self {
            dim,
            n_selected,
            n_max_admitted,
            b_inf,
            b2_sq,
        };
        params.validate()?;
        Ok(params)
    }

    /// Validate the manuscript no-wraparound conditions used in Round 1.
    pub fn validate(&self) -> Result<()> {
        if self.dim == 0 {
            return Err(AvsaError::InvalidParams("dim must be positive".into()));
        }
        if self.n_selected == 0 {
            return Err(AvsaError::InvalidParams(
                "n_selected must be positive".into(),
            ));
        }
        if self.n_max_admitted == 0 {
            return Err(AvsaError::InvalidParams(
                "n_max_admitted must be positive".into(),
            ));
        }
        if self.n_max_admitted > self.n_selected {
            return Err(AvsaError::InvalidParams(
                "n_max_admitted cannot exceed n_selected".into(),
            ));
        }
        if self.b_inf < 0 {
            return Err(AvsaError::InvalidBound("b_inf must be nonnegative".into()));
        }
        if self.b2_sq < 0 {
            return Err(AvsaError::InvalidBound("b2_sq must be nonnegative".into()));
        }

        let coordinate_sum_bound = (self.n_max_admitted as i128)
            .checked_mul(self.b_inf as i128)
            .ok_or_else(|| {
                AvsaError::InvalidParams(
                    "N_max * B_inf overflows the Round 1 host integer check".into(),
                )
            })?;

        if coordinate_sum_bound >= ROUND1_HOST_NO_WRAP_Q_HALF {
            return Err(AvsaError::InvalidParams(
                "N_max * B_inf must be strictly below the no-wraparound bound".into(),
            ));
        }

        if self.b2_sq >= ROUND1_HOST_NO_WRAP_Q_HALF {
            return Err(AvsaError::InvalidParams(
                "B_2^2 must be strictly below the no-wraparound bound".into(),
            ));
        }

        Ok(())
    }
}
