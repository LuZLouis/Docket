use crate::{AvsaError, Result};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

/// Vector over the curve25519 scalar field.
pub type ScalarVector = Vec<Scalar>;

/// Encode a signed host integer as a scalar field element.
pub fn encode_signed_i64(value: i64) -> Scalar {
    if value >= 0 {
        Scalar::from(value as u64)
    } else {
        -Scalar::from(value.unsigned_abs())
    }
}

/// Encode a signed host vector as field elements.
pub fn encode_signed_vector(values: &[i64]) -> ScalarVector {
    values.iter().copied().map(encode_signed_i64).collect()
}

/// Decode a scalar by exhaustive search inside a small centered test bound.
///
/// This is only for simulations and unit tests; arbitrary scalar decoding is a
/// discrete-log problem and is not part of the protocol.
pub fn decode_bounded_scalar(value: &Scalar, bound: i64) -> Result<i64> {
    if bound < 0 {
        return Err(AvsaError::InvalidBound(
            "decode bound must be nonnegative".into(),
        ));
    }
    if *value == Scalar::ZERO {
        return Ok(0);
    }
    for candidate in 1..=bound {
        let encoded = Scalar::from(candidate as u64);
        if *value == encoded {
            return Ok(candidate);
        }
        if *value == -encoded {
            return Ok(-candidate);
        }
    }
    Err(AvsaError::InvalidBound(
        "scalar was outside the supplied centered decode bound".into(),
    ))
}

pub fn decode_bounded_vector(values: &[Scalar], bound: i64) -> Result<Vec<i64>> {
    values
        .iter()
        .map(|value| decode_bounded_scalar(value, bound))
        .collect()
}

pub fn zero_vector(dim: usize) -> ScalarVector {
    vec![Scalar::ZERO; dim]
}

pub fn add_vectors(left: &[Scalar], right: &[Scalar]) -> Result<ScalarVector> {
    ensure_same_len("vector addition", left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right.iter())
        .map(|(left, right)| *left + *right)
        .collect())
}

pub fn sub_vectors(left: &[Scalar], right: &[Scalar]) -> Result<ScalarVector> {
    ensure_same_len("vector subtraction", left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right.iter())
        .map(|(left, right)| *left - *right)
        .collect())
}

pub fn neg_vector(values: &[Scalar]) -> ScalarVector {
    values.iter().map(|value| -*value).collect()
}

pub fn scalar_vectors_equal(left: &[Scalar], right: &[Scalar]) -> bool {
    left == right
}

pub fn inner_product_signed(left: &[i64], right: &[i64]) -> Result<i128> {
    ensure_same_len("signed inner product", left.len(), right.len())?;
    Ok(left
        .iter()
        .zip(right.iter())
        .map(|(left, right)| (*left as i128) * (*right as i128))
        .sum())
}

pub fn signed_vector_sum(vectors: &[&[i64]], dim: usize) -> Result<Vec<i128>> {
    let mut acc = vec![0_i128; dim];
    for vector in vectors {
        ensure_same_len("signed vector sum", dim, vector.len())?;
        for (acc, value) in acc.iter_mut().zip(vector.iter()) {
            *acc += *value as i128;
        }
    }
    Ok(acc)
}

pub fn random_scalar<R: RngCore + ?Sized>(rng: &mut R) -> Scalar {
    let mut wide = [0_u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn random_scalar_vector<R: RngCore + ?Sized>(dim: usize, rng: &mut R) -> ScalarVector {
    (0..dim).map(|_| random_scalar(rng)).collect()
}

pub(crate) fn ensure_same_len(context: &'static str, expected: usize, actual: usize) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(AvsaError::DimensionMismatch {
            context,
            expected,
            actual,
        })
    }
}
