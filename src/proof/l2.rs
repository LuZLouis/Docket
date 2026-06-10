use crate::audit::decision::PredicateVerifier;
use crate::commit::{Generators, PointVector};
use crate::proof::range::{RangeProofBackend, RangeProofContext};
use crate::record::ClientRecord;
use crate::vector::{
    encode_signed_i64, encode_signed_vector, ensure_same_len, random_scalar, random_scalar_vector,
    ScalarVector,
};
use crate::{AvsaError, ClientId, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;

const L2_TRANSCRIPT_LABEL: &[u8] = b"AVSA-Round7-L2Proof-v1";

/// Public L2 statement for one client record.
#[derive(Clone, Copy, Debug)]
pub struct L2Statement<'a> {
    pub rid: &'a str,
    pub client_id: ClientId,
    pub commitments: &'a [RistrettoPoint],
    pub b2_sq: u64,
    pub bit_size: usize,
}

impl<'a> L2Statement<'a> {
    pub fn dim(&self) -> usize {
        self.commitments.len()
    }
}

/// Private witness for the committed input vector.
#[derive(Clone, Copy, Debug)]
pub struct L2Witness<'a> {
    pub values: &'a [i64],
    pub blindings: &'a [Scalar],
}

/// Algorithm 4 L2 proof plus a range-backend proof for the norm/slack bound.
///
/// Manuscript mapping: `norm_commitment` is C_2, `a` is A_j,
/// `c_times` is C_x/C_times, `c_plus` is C_+, `z` is z_j,
/// `theta_commitments` is theta_j, and `theta_norm` is theta.
#[derive(Clone, Debug, PartialEq)]
pub struct L2Proof<P> {
    pub norm_commitment: RistrettoPoint,
    pub slack_commitment: RistrettoPoint,
    pub a: PointVector,
    pub c_times: RistrettoPoint,
    pub c_plus: RistrettoPoint,
    pub z: ScalarVector,
    pub theta_commitments: ScalarVector,
    pub theta_norm: Scalar,
    pub range_proof: P,
}

#[allow(clippy::too_many_arguments)]
pub fn l2_prove<B: RangeProofBackend, R: RngCore + ?Sized>(
    statement: &L2Statement<'_>,
    witness: &L2Witness<'_>,
    generators: &Generators,
    rng: &mut R,
) -> Result<L2Proof<B::Proof>> {
    validate_statement(statement)?;
    validate_witness(statement, witness)?;
    validate_witness_commitments(statement, witness, generators)?;

    let norm_sq = checked_l2_norm_sq(witness.values)?;
    let slack = checked_l2_slack(statement.b2_sq as u128, norm_sq)?;
    let norm_sq_u64 = u128_to_u64(norm_sq, AvsaError::L2NormOverflow)?;
    let slack_u64 = u128_to_u64(slack, AvsaError::InvalidL2Bound("slack exceeds u64"))?;

    let rho2 = random_scalar(rng);
    let norm_commitment = generators.commit_scalar(Scalar::from(norm_sq_u64), rho2);
    let slack_commitment = slack_commitment(statement.b2_sq, &norm_commitment, generators)?;

    let mu = random_scalar_vector(statement.dim(), rng);
    let eta = random_scalar_vector(statement.dim(), rng);
    let a = generators.commit_vector(&mu, &eta)?;

    let x_scalars = encode_signed_vector(witness.values);
    let x_times = scalar_square_sum(&mu);
    let x_plus = Scalar::from(2_u64) * scalar_inner_product(&x_scalars, &mu);
    let rho_times = random_scalar(rng);
    let rho_plus = random_scalar(rng);
    let c_times = generators.commit_scalar(x_times, rho_times);
    let c_plus = generators.commit_scalar(x_plus, rho_plus);

    let range_commitments = vec![norm_commitment, slack_commitment];
    let range_context = l2_range_context(statement, &range_commitments)?;
    let challenge = l2_challenge(
        statement,
        &norm_commitment,
        &slack_commitment,
        &a,
        &c_times,
        &c_plus,
        &range_context.digest(),
        generators,
    )?;

    let z = mu
        .iter()
        .zip(x_scalars.iter())
        .map(|(mu_j, x_j)| *mu_j + challenge * *x_j)
        .collect();
    let theta_commitments = eta
        .iter()
        .zip(witness.blindings.iter())
        .map(|(eta_j, rho_j)| *eta_j + challenge * *rho_j)
        .collect();
    let theta_norm = rho_times + challenge * rho_plus + challenge * challenge * rho2;

    let range_values = vec![norm_sq_u64, slack_u64];
    let range_blindings = vec![rho2, -rho2];
    let range_proof = B::prove_range(
        &range_context,
        &range_commitments,
        &range_values,
        &range_blindings,
        statement.bit_size,
        generators,
    )
    .map_err(|_| AvsaError::InvalidL2RangeProof)?;

    Ok(L2Proof {
        norm_commitment,
        slack_commitment,
        a,
        c_times,
        c_plus,
        z,
        theta_commitments,
        theta_norm,
        range_proof,
    })
}

pub fn l2_verify<B: RangeProofBackend>(
    statement: &L2Statement<'_>,
    proof: &L2Proof<B::Proof>,
    generators: &Generators,
) -> Result<()> {
    validate_statement(statement)?;
    validate_proof_dimensions(statement, proof)?;

    let expected_slack = slack_commitment(statement.b2_sq, &proof.norm_commitment, generators)?;
    if expected_slack != proof.slack_commitment {
        return Err(AvsaError::InvalidSlackCommitment);
    }

    let range_commitments = vec![proof.norm_commitment, proof.slack_commitment];
    let range_context = l2_range_context(statement, &range_commitments)?;
    let challenge = l2_challenge(
        statement,
        &proof.norm_commitment,
        &proof.slack_commitment,
        &proof.a,
        &proof.c_times,
        &proof.c_plus,
        &range_context.digest(),
        generators,
    )?;

    for j in 0..statement.dim() {
        let left = generators.commit_scalar(proof.z[j], proof.theta_commitments[j]);
        let right = proof.a[j] + statement.commitments[j] * challenge;
        if left != right {
            return Err(AvsaError::InvalidQuadraticRelation);
        }
    }

    let z_norm = scalar_square_sum(&proof.z);
    let left = generators.commit_scalar(z_norm, proof.theta_norm);
    let right =
        proof.c_times + proof.c_plus * challenge + proof.norm_commitment * (challenge * challenge);
    if left != right {
        return Err(AvsaError::InvalidQuadraticRelation);
    }

    B::verify_range(
        &range_context,
        &range_commitments,
        &proof.range_proof,
        statement.bit_size,
        generators,
    )
    .map_err(|_| AvsaError::InvalidL2RangeProof)
}

/// Narrow Round 3 predicate adapter for L2 data-validity proofs.
#[derive(Clone, Debug)]
pub struct L2PredicateVerifier<'a, B: RangeProofBackend> {
    pub proofs_by_client: &'a BTreeMap<ClientId, L2Proof<B::Proof>>,
    pub b2_sq: u64,
    pub bit_size: usize,
    pub generators: &'a Generators,
}

impl<'a, B: RangeProofBackend> PredicateVerifier for L2PredicateVerifier<'a, B> {
    fn verify_predicate(&self, record: &ClientRecord) -> Result<()> {
        let proof = self
            .proofs_by_client
            .get(&record.client_id)
            .ok_or(AvsaError::MissingDataProof(record.client_id))?;
        let statement = L2Statement {
            rid: record.round_id.as_str(),
            client_id: record.client_id,
            commitments: &record.commitments,
            b2_sq: self.b2_sq,
            bit_size: self.bit_size,
        };
        l2_verify::<B>(&statement, proof, self.generators)
            .map_err(|_| AvsaError::InvalidPredicateProof)
    }
}

pub fn checked_square_i64(value: i64) -> Result<u128> {
    let magnitude = value.unsigned_abs() as u128;
    magnitude
        .checked_mul(magnitude)
        .ok_or(AvsaError::L2NormOverflow)
}

pub fn checked_l2_norm_sq(values: &[i64]) -> Result<u128> {
    values.iter().try_fold(0_u128, |acc, value| {
        let square = checked_square_i64(*value)?;
        acc.checked_add(square).ok_or(AvsaError::L2NormOverflow)
    })
}

pub fn checked_l2_slack(b2_sq: u128, norm_sq: u128) -> Result<u128> {
    b2_sq
        .checked_sub(norm_sq)
        .ok_or(AvsaError::L2SlackUnderflow)
}

fn validate_statement(statement: &L2Statement<'_>) -> Result<()> {
    if statement.rid.is_empty() {
        return Err(AvsaError::InvalidL2Statement("round id is empty"));
    }
    if statement.commitments.is_empty() {
        return Err(AvsaError::EmptyInput("L2 commitments"));
    }
    if statement.b2_sq == 0 {
        return Err(AvsaError::InvalidL2Bound("B2_sq must be positive"));
    }
    if statement.b2_sq > i64::MAX as u64 {
        return Err(AvsaError::InvalidL2Bound(
            "B2_sq must fit the range-backend bound representation",
        ));
    }
    crate::proof::range::validate_bit_size(statement.b2_sq, statement.bit_size)
        .map_err(|_| AvsaError::InvalidL2Bound("bit size is too small for B2_sq"))?;
    Ok(())
}

fn validate_witness(statement: &L2Statement<'_>, witness: &L2Witness<'_>) -> Result<()> {
    ensure_same_len("L2 witness values", statement.dim(), witness.values.len())
        .map_err(|_| AvsaError::InvalidL2Dimension)?;
    ensure_same_len(
        "L2 witness blindings",
        statement.dim(),
        witness.blindings.len(),
    )
    .map_err(|_| AvsaError::InvalidL2Dimension)?;
    Ok(())
}

fn validate_proof_dimensions<B: Clone>(
    statement: &L2Statement<'_>,
    proof: &L2Proof<B>,
) -> Result<()> {
    ensure_same_len("L2 proof A", statement.dim(), proof.a.len())
        .map_err(|_| AvsaError::InvalidL2Dimension)?;
    ensure_same_len("L2 proof z", statement.dim(), proof.z.len())
        .map_err(|_| AvsaError::InvalidL2Dimension)?;
    ensure_same_len(
        "L2 proof theta_j",
        statement.dim(),
        proof.theta_commitments.len(),
    )
    .map_err(|_| AvsaError::InvalidL2Dimension)?;
    Ok(())
}

fn validate_witness_commitments(
    statement: &L2Statement<'_>,
    witness: &L2Witness<'_>,
    generators: &Generators,
) -> Result<()> {
    for ((commitment, value), blinding) in statement
        .commitments
        .iter()
        .zip(witness.values.iter())
        .zip(witness.blindings.iter())
    {
        let expected = generators.commit_scalar(encode_signed_i64(*value), *blinding);
        if *commitment != expected {
            return Err(AvsaError::InvalidL2Witness(
                "witness does not open the input commitments",
            ));
        }
    }
    Ok(())
}

fn slack_commitment(
    b2_sq: u64,
    norm_commitment: &RistrettoPoint,
    generators: &Generators,
) -> Result<RistrettoPoint> {
    if b2_sq > i64::MAX as u64 {
        return Err(AvsaError::InvalidL2Bound(
            "B2_sq must fit the range-backend bound representation",
        ));
    }
    Ok(generators.g * Scalar::from(b2_sq) - *norm_commitment)
}

fn l2_range_context(
    statement: &L2Statement<'_>,
    range_commitments: &[RistrettoPoint],
) -> Result<RangeProofContext> {
    RangeProofContext::new(
        statement.rid,
        statement.client_id,
        statement.b2_sq,
        statement.bit_size,
        range_commitments,
    )
    .map_err(|_| AvsaError::InvalidL2RangeProof)
}

fn l2_challenge(
    statement: &L2Statement<'_>,
    norm_commitment: &RistrettoPoint,
    slack_commitment: &RistrettoPoint,
    a: &[RistrettoPoint],
    c_times: &RistrettoPoint,
    c_plus: &RistrettoPoint,
    range_context_digest: &[u8; 32],
    generators: &Generators,
) -> Result<Scalar> {
    ensure_same_len("L2 transcript A", statement.dim(), a.len())
        .map_err(|_| AvsaError::InvalidL2Transcript)?;

    let mut hasher = Sha512::new();
    hasher.update(L2_TRANSCRIPT_LABEL);
    push_len_prefixed_hasher(&mut hasher, statement.rid.as_bytes());
    hasher.update(statement.client_id.to_le_bytes());
    hasher.update((statement.dim() as u64).to_le_bytes());
    hasher.update(statement.b2_sq.to_le_bytes());
    hasher.update((statement.bit_size as u64).to_le_bytes());
    push_point_hasher(&mut hasher, &generators.g);
    push_point_hasher(&mut hasher, &generators.h);
    push_point_slice_hasher(&mut hasher, statement.commitments);
    push_point_hasher(&mut hasher, norm_commitment);
    push_point_hasher(&mut hasher, slack_commitment);
    push_point_slice_hasher(&mut hasher, a);
    push_point_hasher(&mut hasher, c_times);
    push_point_hasher(&mut hasher, c_plus);
    hasher.update(range_context_digest);

    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide.copy_from_slice(&digest);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn scalar_inner_product(left: &[Scalar], right: &[Scalar]) -> Scalar {
    left.iter()
        .zip(right.iter())
        .fold(Scalar::ZERO, |acc, (left, right)| acc + *left * *right)
}

fn scalar_square_sum(values: &[Scalar]) -> Scalar {
    scalar_inner_product(values, values)
}

fn u128_to_u64(value: u128, err: AvsaError) -> Result<u64> {
    if value <= u64::MAX as u128 {
        Ok(value as u64)
    } else {
        Err(err)
    }
}

fn push_len_prefixed_hasher(hasher: &mut Sha512, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn push_point_hasher(hasher: &mut Sha512, point: &RistrettoPoint) {
    hasher.update(point.compress().as_bytes());
}

fn push_point_slice_hasher(hasher: &mut Sha512, points: &[RistrettoPoint]) {
    hasher.update((points.len() as u64).to_le_bytes());
    for point in points {
        push_point_hasher(hasher, point);
    }
}
