use crate::vector::ensure_same_len;
use crate::{AvsaError, Result};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// Vector of Ristretto points used for commitments and tags.
pub type PointVector = Vec<RistrettoPoint>;

/// Compact homomorphic tag Tag(v)=prod_j k_j^{v_j}, in additive notation.
pub type MaskTag = RistrettoPoint;

/// Public deterministic vector-tag bases.
#[derive(Clone, Debug, PartialEq)]
pub struct TagBases {
    pub seed: [u8; 32],
    pub bases: Vec<RistrettoPoint>,
}

static TAG_BASE_CACHE: OnceLock<Mutex<BTreeMap<([u8; 32], usize), TagBases>>> = OnceLock::new();

/// Independent generators for data commitments and mask tags.
#[derive(Clone, Debug)]
pub struct Generators {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub k: RistrettoPoint,
}

impl Default for Generators {
    fn default() -> Self {
        Self {
            g: RISTRETTO_BASEPOINT_POINT,
            h: point_from_label(b"AVSA Round 1 Pedersen h"),
            k: point_from_label(b"AVSA Round 1 mask tag k"),
        }
    }
}

impl Generators {
    /// Pedersen commitment C = g^x h^rho, using additive group notation.
    pub fn commit_scalar(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        self.g * value + self.h * blinding
    }

    /// Coordinate-wise Pedersen commitments.
    pub fn commit_vector(&self, values: &[Scalar], blindings: &[Scalar]) -> Result<PointVector> {
        ensure_same_len("vector commitment", values.len(), blindings.len())?;
        Ok(values
            .iter()
            .zip(blindings.iter())
            .map(|(value, blinding)| self.commit_scalar(*value, *blinding))
            .collect())
    }

    /// Mask tag k^v, represented as scalar multiplication of the tag generator.
    pub fn tag_scalar(&self, value: Scalar) -> RistrettoPoint {
        self.k * value
    }

    /// Default compact vector tag bases for the supplied dimension.
    pub fn tag_bases(&self, dim: usize) -> TagBases {
        let digest = Sha512::digest(
            [
                b"AVSA compact vector tag seed v1".as_slice(),
                self.k.compress().as_bytes(),
            ]
            .concat(),
        );
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest[..32]);
        cached_tag_bases(seed, dim)
    }

    /// Compact homomorphic vector tag.
    pub fn tag_vector(&self, values: &[Scalar]) -> Result<MaskTag> {
        let bases = self.tag_bases(values.len());
        tag_vector(&bases, values)
    }
}

pub fn derive_tag_bases(seed: [u8; 32], dim: usize) -> TagBases {
    let mut bases = Vec::with_capacity(dim);
    for index in 0..dim {
        let mut hasher = Sha512::new();
        hasher.update(b"AVSA compact vector tag base v1");
        hasher.update(seed);
        hasher.update((index as u64).to_le_bytes());
        let digest = hasher.finalize();
        let mut uniform = [0_u8; 64];
        uniform.copy_from_slice(&digest);
        bases.push(RistrettoPoint::from_uniform_bytes(&uniform));
    }
    TagBases { seed, bases }
}

pub fn cached_tag_bases(seed: [u8; 32], dim: usize) -> TagBases {
    let cache = TAG_BASE_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache.lock().expect("tag base cache poisoned");
    cache
        .entry((seed, dim))
        .or_insert_with(|| derive_tag_bases(seed, dim))
        .clone()
}

pub fn tag_vector(bases: &TagBases, values: &[Scalar]) -> Result<MaskTag> {
    ensure_same_len("compact vector tag", bases.bases.len(), values.len())?;
    if values.is_empty() {
        return Err(AvsaError::EmptyInput("compact vector tag"));
    }
    Ok(RistrettoPoint::multiscalar_mul(
        values.iter().copied(),
        bases.bases.iter().copied(),
    ))
}

pub fn add_point_vectors(left: &[RistrettoPoint], right: &[RistrettoPoint]) -> Result<PointVector> {
    ensure_same_len("point vector addition", left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right.iter())
        .map(|(left, right)| *left + *right)
        .collect())
}

pub fn sub_point_vectors(left: &[RistrettoPoint], right: &[RistrettoPoint]) -> Result<PointVector> {
    ensure_same_len("point vector subtraction", left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right.iter())
        .map(|(left, right)| *left - *right)
        .collect())
}

pub fn neg_point_vector(values: &[RistrettoPoint]) -> PointVector {
    values.iter().map(|value| -*value).collect()
}

pub fn zero_point_vector(dim: usize) -> PointVector {
    vec![RistrettoPoint::identity(); dim]
}

pub fn point_vectors_equal(left: &[RistrettoPoint], right: &[RistrettoPoint]) -> bool {
    left == right
}

fn point_from_label(label: &[u8]) -> RistrettoPoint {
    let digest = Sha512::digest(label);
    let mut uniform = [0_u8; 64];
    uniform.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&uniform)
}
