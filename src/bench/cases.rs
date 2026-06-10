use crate::{AvsaError, Result};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchBackend {
    Mock,
    Bulletproofs,
}

impl BenchBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Bulletproofs => "bulletproofs",
        }
    }
}

impl fmt::Display for BenchBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BenchBackend {
    type Err = AvsaError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "mock" => Ok(Self::Mock),
            "bulletproofs" => Ok(Self::Bulletproofs),
            other => Err(AvsaError::UnsupportedBenchBackend(other.into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchPreset {
    Smoke,
    Small,
    Medium,
    MnistLike,
    Cifar10SLike,
    Cifar10LLike,
    ShakespeareLike,
}

impl BenchPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::MnistLike => "mnist_like",
            Self::Cifar10SLike => "cifar10_s_like",
            Self::Cifar10LLike => "cifar10_l_like",
            Self::ShakespeareLike => "shakespeare_like",
        }
    }

    pub fn defaults(self) -> PresetDefaults {
        match self {
            Self::Smoke => PresetDefaults {
                n_selected: 4,
                dim: 8,
            },
            Self::Small => PresetDefaults {
                n_selected: 8,
                dim: 64,
            },
            Self::Medium => PresetDefaults {
                n_selected: 16,
                dim: 1024,
            },
            Self::MnistLike => PresetDefaults {
                n_selected: 16,
                dim: 19_000,
            },
            Self::Cifar10SLike => PresetDefaults {
                n_selected: 16,
                dim: 62_000,
            },
            Self::Cifar10LLike => PresetDefaults {
                n_selected: 16,
                dim: 273_000,
            },
            Self::ShakespeareLike => PresetDefaults {
                n_selected: 16,
                dim: 818_000,
            },
        }
    }
}

impl fmt::Display for BenchPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BenchPreset {
    type Err = AvsaError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "small" => Ok(Self::Small),
            "medium" => Ok(Self::Medium),
            "mnist_like" => Ok(Self::MnistLike),
            "cifar10_s_like" => Ok(Self::Cifar10SLike),
            "cifar10_l_like" => Ok(Self::Cifar10LLike),
            "shakespeare_like" => Ok(Self::ShakespeareLike),
            other => Err(AvsaError::UnsupportedBenchPreset(other.into())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresetDefaults {
    pub n_selected: usize,
    pub dim: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchConfig {
    pub preset: BenchPreset,
    pub backend: BenchBackend,
    pub n_selected: usize,
    pub n_admitted: usize,
    pub n_dropped: usize,
    pub n_rejected: usize,
    pub dim: usize,
    pub b_inf: i64,
    pub b2_sq: u128,
    pub bit_size: usize,
    pub iters: usize,
    pub warmup: usize,
    pub seed: u64,
    pub out_dir: PathBuf,
    pub allow_failures: bool,
}

impl BenchConfig {
    pub fn for_preset(preset: BenchPreset) -> Self {
        let defaults = preset.defaults();
        let b_inf = 3_i64;
        let b2_sq = default_b2_sq(defaults.dim, b_inf);
        Self {
            preset,
            backend: BenchBackend::Mock,
            n_selected: defaults.n_selected,
            n_admitted: defaults.n_selected.saturating_sub(1).max(1),
            n_dropped: 1.min(defaults.n_selected.saturating_sub(1)),
            n_rejected: 0,
            dim: defaults.dim,
            b_inf,
            b2_sq,
            bit_size: bit_size_for_bound(b2_sq),
            iters: 1,
            warmup: 0,
            seed: 42,
            out_dir: PathBuf::from("target/avsa_bench"),
            allow_failures: false,
        }
    }

    pub fn case_name(&self) -> &'static str {
        self.preset.as_str()
    }

    pub fn run_id(&self) -> String {
        format!(
            "{}-{}-seed{}-n{}-d{}",
            self.case_name(),
            self.backend.as_str(),
            self.seed,
            self.n_selected,
            self.dim
        )
    }

    pub fn selected_clients(&self) -> Result<Vec<u64>> {
        if self.n_selected == 0 {
            return Err(AvsaError::InvalidBenchConfig(
                "n_selected must be positive".into(),
            ));
        }
        Ok((1..=self.n_selected as u64).collect())
    }

    pub fn admitted_clients(&self) -> Result<Vec<u64>> {
        self.validate()?;
        Ok((1..=self.n_admitted as u64).collect())
    }

    pub fn dropped_clients(&self) -> Result<Vec<u64>> {
        self.validate()?;
        let start = self.n_admitted.saturating_add(1);
        let end = self.n_admitted.saturating_add(self.n_dropped);
        Ok((start..=end)
            .filter(|client| *client <= self.n_selected)
            .map(|client| client as u64)
            .collect())
    }

    pub fn rejected_clients(&self) -> Result<Vec<u64>> {
        self.validate()?;
        let dropped_end = self.n_admitted.saturating_add(self.n_dropped);
        let start = dropped_end.saturating_add(1);
        let end = dropped_end.saturating_add(self.n_rejected);
        Ok((start..=end)
            .filter(|client| *client <= self.n_selected)
            .map(|client| client as u64)
            .collect())
    }

    pub fn validate(&self) -> Result<()> {
        if self.dim == 0 {
            return Err(AvsaError::InvalidBenchConfig("dim must be positive".into()));
        }
        if self.b_inf <= 0 {
            return Err(AvsaError::InvalidBenchConfig(
                "b_inf must be positive".into(),
            ));
        }
        if self.b2_sq == 0 || self.b2_sq > i64::MAX as u128 {
            return Err(AvsaError::InvalidBenchConfig(
                "b2_sq must be in 1..=i64::MAX for the current L2 range wrapper".into(),
            ));
        }
        crate::proof::range::validate_bit_size(self.b_inf as u64, self.bit_size).map_err(|_| {
            AvsaError::InvalidBenchConfig(
                "bit_size must be large enough for the signed range bound".into(),
            )
        })?;
        crate::proof::range::validate_bit_size(self.b2_sq as u64, self.bit_size).map_err(|_| {
            AvsaError::InvalidBenchConfig("bit_size must be large enough for the L2 bound".into())
        })?;
        if self.iters == 0 {
            return Err(AvsaError::InvalidBenchConfig(
                "iters must be positive".into(),
            ));
        }
        if self.n_selected == 0 || self.n_admitted == 0 {
            return Err(AvsaError::InvalidBenchConfig(
                "n_selected and n_admitted must be positive".into(),
            ));
        }
        if self.n_admitted > self.n_selected {
            return Err(AvsaError::InvalidBenchConfig(
                "n_admitted cannot exceed n_selected".into(),
            ));
        }
        let classified = self
            .n_admitted
            .checked_add(self.n_dropped)
            .and_then(|value| value.checked_add(self.n_rejected))
            .ok_or_else(|| AvsaError::InvalidBenchConfig("client counts overflow".into()))?;
        if classified > self.n_selected {
            return Err(AvsaError::InvalidBenchConfig(
                "admitted + dropped + rejected cannot exceed selected".into(),
            ));
        }
        Ok(())
    }
}

pub fn default_b2_sq(dim: usize, b_inf: i64) -> u128 {
    let bound = b_inf.unsigned_abs() as u128;
    (dim as u128).saturating_mul(bound).saturating_mul(bound)
}

pub fn bit_size_for_bound(bound: u128) -> usize {
    let needed = bound.saturating_mul(2).saturating_add(1);
    let bits = 128_usize - needed.saturating_sub(1).leading_zeros() as usize;
    match bits.max(1) {
        1..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        _ => 64,
    }
}
