use crate::audit::decision::PredicateVerifier;
use crate::commit::{Generators, PointVector};
use crate::record::ClientRecord;
use crate::vector::{ensure_same_len, ScalarVector};
use crate::{AvsaError, ClientId, Result};
#[cfg(feature = "bulletproofs-backend")]
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[cfg(feature = "bulletproofs-backend")]
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
#[cfg(feature = "bulletproofs-backend")]
use merlin::Transcript;

const RANGE_PROTOCOL_LABEL: &[u8] = b"AVSA-Round5-SignedRange-v1";
#[cfg(feature = "bulletproofs-backend")]
const BULLETPROOFS_TRANSCRIPT_LABEL: &[u8] = b"AVSA-Round6-BulletproofsRange-v1";
#[cfg(feature = "bulletproofs-backend")]
const BULLETPROOFS_MAX_SHIFTED_VALUES_PER_PROOF: usize = 1024;

/// Deterministic public context bound into a range proof transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProofContext {
    pub protocol_label: &'static [u8],
    pub round_id: String,
    pub client_id: ClientId,
    pub dimension: usize,
    pub b_inf: u64,
    pub bit_size: usize,
    pub shifted_commitment_digest: [u8; 32],
}

impl RangeProofContext {
    pub fn new(
        round_id: impl Into<String>,
        client_id: ClientId,
        b_inf: u64,
        bit_size: usize,
        shifted_commitments: &[RistrettoPoint],
    ) -> Result<Self> {
        validate_range_bound(b_inf)?;
        validate_bit_size(b_inf, bit_size)?;
        if shifted_commitments.is_empty() {
            return Err(AvsaError::EmptyInput("range shifted commitments"));
        }

        Ok(Self {
            protocol_label: RANGE_PROTOCOL_LABEL,
            round_id: round_id.into(),
            client_id,
            dimension: shifted_commitments.len(),
            b_inf,
            bit_size,
            shifted_commitment_digest: shifted_commitment_digest(shifted_commitments),
        })
    }

    /// Canonical digest of the context. This never hashes Debug output.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        push_len_prefixed_hasher(&mut hasher, self.protocol_label);
        push_len_prefixed_hasher(&mut hasher, self.round_id.as_bytes());
        hasher.update(self.client_id.to_le_bytes());
        hasher.update((self.dimension as u64).to_le_bytes());
        hasher.update(self.b_inf.to_le_bytes());
        hasher.update((self.bit_size as u64).to_le_bytes());
        hasher.update(self.shifted_commitment_digest);
        finish_sha256(hasher)
    }
}

/// Backend interface for unsigned range proofs over shifted Pedersen commitments.
///
/// Backends receive only the non-negative shifted values and commitments. They
/// are independent of AVSA mask/tag internals and use only the existing
/// Pedersen generators `g` and `h` from `Generators`.
pub trait RangeProofBackend {
    type Proof: Clone;

    fn prove_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        shifted_values: &[u64],
        blindings: &[Scalar],
        bit_size: usize,
        generators: &Generators,
    ) -> Result<Self::Proof>;

    fn verify_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        proof: &Self::Proof,
        bit_size: usize,
        generators: &Generators,
    ) -> Result<()>;
}

/// Signed AVSA range predicate proof wrapper.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedRangeProof<P> {
    pub b_inf: u64,
    pub bit_size: usize,
    pub shifted_commitments: PointVector,
    pub backend_proof: P,
}

/// Test-only backend. Not cryptographically secure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockRangeProofBackend;

/// Test-only proof payload. It intentionally reveals witnesses for unit tests.
#[derive(Clone, Debug, PartialEq)]
pub struct MockRangeProof {
    pub context_digest: [u8; 32],
    pub shifted_values: Vec<u64>,
    pub blindings: ScalarVector,
}

/// Real Bulletproofs range-proof backend for AVSA shifted commitments.
///
/// The external Round 5 statement remains `C+ = C * g^B`. Internally the
/// backend derives Algorithm 3's complement commitment `C- = g^{2B} / C+` and
/// proves both shifted values are nonnegative, which enforces the exact signed
/// interval for arbitrary `B`.
#[cfg(feature = "bulletproofs-backend")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BulletproofsRangeBackend;

/// Serialized Bulletproofs proof payload.
///
/// This object intentionally stores no signed values, shifted values, or
/// blindings.
#[cfg(feature = "bulletproofs-backend")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulletproofsRangeProof {
    pub proof_chunks: Vec<BulletproofsRangeProofChunk>,
}

/// One Bulletproofs range proof over a deterministic chunk of shifted values.
#[cfg(feature = "bulletproofs-backend")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulletproofsRangeProofChunk {
    pub proof_bytes: Vec<u8>,
}

impl RangeProofBackend for MockRangeProofBackend {
    type Proof = MockRangeProof;

    fn prove_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        shifted_values: &[u64],
        blindings: &[Scalar],
        bit_size: usize,
        generators: &Generators,
    ) -> Result<Self::Proof> {
        validate_backend_inputs(
            context,
            shifted_commitments,
            shifted_values,
            blindings,
            bit_size,
        )?;
        validate_shifted_values(shifted_values, bit_size, context.b_inf)?;
        validate_commitment_openings(shifted_commitments, shifted_values, blindings, generators)?;

        Ok(MockRangeProof {
            context_digest: context.digest(),
            shifted_values: shifted_values.to_vec(),
            blindings: blindings.to_vec(),
        })
    }

    fn verify_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        proof: &Self::Proof,
        bit_size: usize,
        generators: &Generators,
    ) -> Result<()> {
        if context.digest() != proof.context_digest {
            return Err(AvsaError::InvalidRangeProofContext(
                "context digest mismatch",
            ));
        }
        validate_backend_inputs(
            context,
            shifted_commitments,
            &proof.shifted_values,
            &proof.blindings,
            bit_size,
        )?;
        validate_shifted_values(&proof.shifted_values, bit_size, context.b_inf)?;
        validate_commitment_openings(
            shifted_commitments,
            &proof.shifted_values,
            &proof.blindings,
            generators,
        )
    }
}

#[cfg(feature = "bulletproofs-backend")]
impl RangeProofBackend for BulletproofsRangeBackend {
    type Proof = BulletproofsRangeProof;

    fn prove_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        shifted_values: &[u64],
        blindings: &[Scalar],
        bit_size: usize,
        generators: &Generators,
    ) -> Result<Self::Proof> {
        validate_backend_inputs(
            context,
            shifted_commitments,
            shifted_values,
            blindings,
            bit_size,
        )?;
        validate_shifted_values(shifted_values, bit_size, context.b_inf)?;
        validate_commitment_openings(shifted_commitments, shifted_values, blindings, generators)?;

        let pc_gens = bulletproofs_pedersen_generators(generators);
        let chunks = bulletproof_chunk_ranges(shifted_values.len());
        let mut proof_chunks = Vec::with_capacity(chunks.len());

        for (chunk_index, start, end) in chunks {
            let mut range_values =
                bulletproof_range_values(&shifted_values[start..end], context.b_inf)?;
            let mut range_blindings = bulletproof_range_blindings(&blindings[start..end]);
            let mut range_commitments = bulletproof_range_commitments(
                &shifted_commitments[start..end],
                context.b_inf,
                generators,
            )?;
            let padded_count = pad_bulletproof_chunk(
                &mut range_values,
                &mut range_blindings,
                &mut range_commitments,
                generators,
            )?;
            validate_bulletproof_parameters(bit_size, padded_count)?;

            let bp_gens = BulletproofGens::new(bit_size, padded_count);
            let mut transcript =
                bulletproofs_transcript(context, chunk_index, start, end, padded_count);
            let (proof, generated_commitments) = RangeProof::prove_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &range_values,
                &range_blindings,
                bit_size,
            )
            .map_err(|err| AvsaError::BulletproofsBackendError(err.to_string()))?;

            let expected_commitments = compress_points(&range_commitments);
            if generated_commitments != expected_commitments {
                return Err(AvsaError::InvalidRangeCommitment);
            }

            proof_chunks.push(BulletproofsRangeProofChunk {
                proof_bytes: proof.to_bytes(),
            });
        }

        Ok(BulletproofsRangeProof { proof_chunks })
    }

    fn verify_range(
        context: &RangeProofContext,
        shifted_commitments: &[RistrettoPoint],
        proof: &Self::Proof,
        bit_size: usize,
        generators: &Generators,
    ) -> Result<()> {
        validate_bit_size(context.b_inf, bit_size)?;
        if context.protocol_label != RANGE_PROTOCOL_LABEL {
            return Err(AvsaError::InvalidRangeProofContext(
                "protocol label mismatch",
            ));
        }
        ensure_same_len(
            "Bulletproofs range commitments",
            context.dimension,
            shifted_commitments.len(),
        )
        .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
        if context.bit_size != bit_size {
            return Err(AvsaError::InvalidRangeProofContext(
                "context bit_size mismatch",
            ));
        }
        if shifted_commitment_digest(shifted_commitments) != context.shifted_commitment_digest {
            return Err(AvsaError::InvalidRangeProofContext(
                "commitment digest mismatch",
            ));
        }
        let pc_gens = bulletproofs_pedersen_generators(generators);
        let chunks = bulletproof_chunk_ranges(shifted_commitments.len());
        if proof.proof_chunks.len() != chunks.len() {
            return Err(AvsaError::InvalidRangeProofDimension);
        }

        for ((chunk_index, start, end), proof_chunk) in chunks.into_iter().zip(&proof.proof_chunks)
        {
            let mut range_commitments = bulletproof_range_commitments(
                &shifted_commitments[start..end],
                context.b_inf,
                generators,
            )?;
            let padded_count =
                pad_bulletproof_commitment_chunk(&mut range_commitments, generators)?;
            validate_bulletproof_parameters(bit_size, padded_count)?;

            let range_proof = RangeProof::from_bytes(&proof_chunk.proof_bytes).map_err(|_| {
                AvsaError::InvalidRangeProof("Bulletproofs proof deserialization failed")
            })?;
            let bp_gens = BulletproofGens::new(bit_size, padded_count);
            let compressed_commitments = compress_points(&range_commitments);
            let mut transcript =
                bulletproofs_transcript(context, chunk_index, start, end, padded_count);

            range_proof
                .verify_multiple(
                    &bp_gens,
                    &pc_gens,
                    &mut transcript,
                    &compressed_commitments,
                    bit_size,
                )
                .map_err(|_| AvsaError::InvalidRangeProof("Bulletproofs verification failed"))?;
        }

        Ok(())
    }
}

/// Prove `x_j in [-B, B]` by shifting to `y_j = x_j + B`.
#[allow(clippy::too_many_arguments)]
pub fn signed_range_prove<B: RangeProofBackend>(
    round_id: impl Into<String>,
    client_id: ClientId,
    commitments: &[RistrettoPoint],
    signed_values: &[i64],
    blindings: &[Scalar],
    b_inf: u64,
    bit_size: usize,
    generators: &Generators,
) -> Result<SignedRangeProof<B::Proof>> {
    validate_range_bound(b_inf)?;
    validate_bit_size(b_inf, bit_size)?;
    validate_signed_range_dimensions(commitments, signed_values, blindings)?;

    let shifted_values = shift_signed_values(signed_values, b_inf)?;
    let shifted_commitments = shift_commitments(commitments, b_inf, generators)?;
    let context =
        RangeProofContext::new(round_id, client_id, b_inf, bit_size, &shifted_commitments)?;
    let backend_proof = B::prove_range(
        &context,
        &shifted_commitments,
        &shifted_values,
        blindings,
        bit_size,
        generators,
    )?;

    Ok(SignedRangeProof {
        b_inf,
        bit_size,
        shifted_commitments,
        backend_proof,
    })
}

/// Verify a signed range proof without access to `x_j` or `rho_j`.
pub fn signed_range_verify<B: RangeProofBackend>(
    round_id: impl Into<String>,
    client_id: ClientId,
    commitments: &[RistrettoPoint],
    proof: &SignedRangeProof<B::Proof>,
    generators: &Generators,
) -> Result<()> {
    validate_range_bound(proof.b_inf)?;
    validate_bit_size(proof.b_inf, proof.bit_size)?;
    if commitments.is_empty() {
        return Err(AvsaError::EmptyInput("range commitments"));
    }
    ensure_same_len(
        "signed range shifted commitments",
        commitments.len(),
        proof.shifted_commitments.len(),
    )
    .map_err(|_| AvsaError::InvalidRangeProofDimension)?;

    let recomputed = shift_commitments(commitments, proof.b_inf, generators)?;
    if recomputed != proof.shifted_commitments {
        return Err(AvsaError::InvalidShiftedCommitment);
    }

    let context = RangeProofContext::new(
        round_id,
        client_id,
        proof.b_inf,
        proof.bit_size,
        &proof.shifted_commitments,
    )?;
    B::verify_range(
        &context,
        &proof.shifted_commitments,
        &proof.backend_proof,
        proof.bit_size,
        generators,
    )
}

/// Minimal sidecar adapter from Round 3 decision predicates to signed range proofs.
///
/// The existing `ClientRecord` keeps a non-generic data-proof placeholder, so
/// this adapter binds proofs by client id and verifies them against the
/// record's root-bound commitments without redesigning transcript records.
#[derive(Clone, Debug)]
pub struct SignedRangePredicateVerifier<'a, B: RangeProofBackend> {
    pub proofs_by_client: &'a BTreeMap<ClientId, SignedRangeProof<B::Proof>>,
    pub generators: &'a Generators,
}

impl<'a, B: RangeProofBackend> PredicateVerifier for SignedRangePredicateVerifier<'a, B> {
    fn verify_predicate(&self, record: &ClientRecord) -> Result<()> {
        let proof = self
            .proofs_by_client
            .get(&record.client_id)
            .ok_or(AvsaError::MissingDataProof(record.client_id))?;
        signed_range_verify::<B>(
            record.round_id.as_str(),
            record.client_id,
            &record.commitments,
            proof,
            self.generators,
        )
        .map_err(|_| AvsaError::InvalidPredicateProof)
    }
}

pub fn validate_range_bound(b_inf: u64) -> Result<()> {
    if b_inf == 0 {
        return Err(AvsaError::InvalidRangeBound("B must be positive"));
    }
    if b_inf > i64::MAX as u64 {
        return Err(AvsaError::InvalidRangeBound(
            "B must fit the signed host representation",
        ));
    }
    Ok(())
}

pub fn validate_bit_size(b_inf: u64, bit_size: usize) -> Result<()> {
    validate_range_bound(b_inf)?;
    if bit_size == 0 || bit_size > 64 {
        return Err(AvsaError::InvalidRangeBitSize("bit_size must be in 1..=64"));
    }

    let shifted_upper_exclusive = 1_u128 << bit_size;
    let max_shifted_value = 2_u128 * b_inf as u128;
    if max_shifted_value >= shifted_upper_exclusive {
        return Err(AvsaError::InvalidRangeBitSize(
            "bit_size must satisfy 2B < 2^bit_size",
        ));
    }
    Ok(())
}

#[cfg(feature = "bulletproofs-backend")]
pub fn validate_bulletproof_bit_size(bit_size: usize) -> Result<()> {
    match bit_size {
        8 | 16 | 32 | 64 => Ok(()),
        unsupported => Err(AvsaError::UnsupportedRangeBitSize(unsupported)),
    }
}

pub fn shift_signed_value(value: i64, b_inf: u64) -> Result<u64> {
    validate_range_bound(b_inf)?;
    let bound = b_inf as i128;
    let signed = value as i128;
    if signed < -bound || signed > bound {
        return Err(AvsaError::SignedValueOutOfRange);
    }
    Ok((signed + bound) as u64)
}

pub fn shift_signed_values(values: &[i64], b_inf: u64) -> Result<Vec<u64>> {
    values
        .iter()
        .copied()
        .map(|value| shift_signed_value(value, b_inf))
        .collect()
}

pub fn shift_commitments(
    commitments: &[RistrettoPoint],
    b_inf: u64,
    generators: &Generators,
) -> Result<PointVector> {
    validate_range_bound(b_inf)?;
    if commitments.is_empty() {
        return Err(AvsaError::EmptyInput("range commitments"));
    }
    let shift = generators.g * Scalar::from(b_inf);
    Ok(commitments
        .iter()
        .map(|commitment| *commitment + shift)
        .collect())
}

pub fn shifted_commitment_digest(commitments: &[RistrettoPoint]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        hasher.update(commitment.compress().as_bytes());
    }
    finish_sha256(hasher)
}

fn validate_signed_range_dimensions(
    commitments: &[RistrettoPoint],
    signed_values: &[i64],
    blindings: &[Scalar],
) -> Result<()> {
    if commitments.is_empty() {
        return Err(AvsaError::EmptyInput("range commitments"));
    }
    ensure_same_len(
        "signed range values",
        commitments.len(),
        signed_values.len(),
    )
    .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    ensure_same_len("signed range blindings", commitments.len(), blindings.len())
        .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    Ok(())
}

fn validate_backend_inputs(
    context: &RangeProofContext,
    shifted_commitments: &[RistrettoPoint],
    shifted_values: &[u64],
    blindings: &[Scalar],
    bit_size: usize,
) -> Result<()> {
    validate_bit_size(context.b_inf, bit_size)?;
    if context.protocol_label != RANGE_PROTOCOL_LABEL {
        return Err(AvsaError::InvalidRangeProofContext(
            "protocol label mismatch",
        ));
    }
    if context.dimension == 0 || shifted_commitments.is_empty() {
        return Err(AvsaError::EmptyInput("range backend commitments"));
    }
    if context.bit_size != bit_size {
        return Err(AvsaError::InvalidRangeProofContext(
            "context bit_size mismatch",
        ));
    }
    ensure_same_len(
        "range backend commitments",
        context.dimension,
        shifted_commitments.len(),
    )
    .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    ensure_same_len(
        "range backend values",
        shifted_commitments.len(),
        shifted_values.len(),
    )
    .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    ensure_same_len(
        "range backend blindings",
        shifted_commitments.len(),
        blindings.len(),
    )
    .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    if shifted_commitment_digest(shifted_commitments) != context.shifted_commitment_digest {
        return Err(AvsaError::InvalidRangeProofContext(
            "commitment digest mismatch",
        ));
    }
    Ok(())
}

fn validate_shifted_values(values: &[u64], bit_size: usize, b_inf: u64) -> Result<()> {
    let upper_exclusive = 1_u128 << bit_size;
    let signed_upper_inclusive = 2_u128 * b_inf as u128;
    for value in values {
        if (*value as u128) >= upper_exclusive {
            return Err(AvsaError::InvalidRangeProof(
                "shifted value outside unsigned bit range",
            ));
        }
        if (*value as u128) > signed_upper_inclusive {
            return Err(AvsaError::InvalidRangeProof(
                "shifted value outside signed bound",
            ));
        }
    }
    Ok(())
}

fn validate_commitment_openings(
    commitments: &[RistrettoPoint],
    values: &[u64],
    blindings: &[Scalar],
    generators: &Generators,
) -> Result<()> {
    for ((commitment, value), blinding) in commitments.iter().zip(values.iter()).zip(blindings) {
        let expected = generators.commit_scalar(Scalar::from(*value), *blinding);
        if *commitment != expected {
            return Err(AvsaError::InvalidRangeCommitment);
        }
    }
    Ok(())
}

#[cfg(feature = "bulletproofs-backend")]
fn validate_bulletproof_parameters(bit_size: usize, aggregation_size: usize) -> Result<()> {
    validate_bulletproof_bit_size(bit_size)?;
    if aggregation_size == 0 || !aggregation_size.is_power_of_two() {
        return Err(AvsaError::InvalidRangeProofDimension);
    }
    Ok(())
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproof_chunk_ranges(total_shifted_values: usize) -> Vec<(usize, usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < total_shifted_values {
        let end = (start + BULLETPROOFS_MAX_SHIFTED_VALUES_PER_PROOF).min(total_shifted_values);
        ranges.push((ranges.len(), start, end));
        start = end;
    }
    ranges
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproofs_pedersen_generators(generators: &Generators) -> PedersenGens {
    PedersenGens {
        B: generators.g,
        B_blinding: generators.h,
    }
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproof_range_values(shifted_values: &[u64], b_inf: u64) -> Result<Vec<u64>> {
    let two_b = two_b(b_inf)?;
    let mut values = Vec::with_capacity(shifted_values.len() * 2);
    values.extend_from_slice(shifted_values);
    for value in shifted_values {
        let complement = two_b
            .checked_sub(*value)
            .ok_or(AvsaError::InvalidRangeProof("shifted value exceeds 2B"))?;
        values.push(complement);
    }
    Ok(values)
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproof_range_blindings(blindings: &[Scalar]) -> Vec<Scalar> {
    let mut range_blindings = Vec::with_capacity(blindings.len() * 2);
    range_blindings.extend_from_slice(blindings);
    range_blindings.extend(blindings.iter().map(|blinding| -*blinding));
    range_blindings
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproof_range_commitments(
    shifted_commitments: &[RistrettoPoint],
    b_inf: u64,
    generators: &Generators,
) -> Result<PointVector> {
    let two_b_shift = generators.g * Scalar::from(two_b(b_inf)?);
    let mut commitments = Vec::with_capacity(shifted_commitments.len() * 2);
    commitments.extend_from_slice(shifted_commitments);
    commitments.extend(
        shifted_commitments
            .iter()
            .map(|shifted_commitment| two_b_shift - *shifted_commitment),
    );
    Ok(commitments)
}

#[cfg(feature = "bulletproofs-backend")]
fn pad_bulletproof_chunk(
    values: &mut Vec<u64>,
    blindings: &mut Vec<Scalar>,
    commitments: &mut PointVector,
    generators: &Generators,
) -> Result<usize> {
    ensure_same_len("Bulletproofs chunk values", values.len(), blindings.len())
        .map_err(|_| AvsaError::InvalidRangeProofDimension)?;
    let padded_count = pad_bulletproof_commitment_chunk(commitments, generators)?;
    while values.len() < padded_count {
        values.push(0);
        blindings.push(Scalar::ZERO);
    }
    Ok(padded_count)
}

#[cfg(feature = "bulletproofs-backend")]
fn pad_bulletproof_commitment_chunk(
    commitments: &mut PointVector,
    generators: &Generators,
) -> Result<usize> {
    if commitments.is_empty() {
        return Err(AvsaError::InvalidRangeProofDimension);
    }
    let padded_count = commitments
        .len()
        .checked_next_power_of_two()
        .ok_or(AvsaError::InvalidRangeProofDimension)?;
    let zero_commitment = generators.g * Scalar::ZERO;
    while commitments.len() < padded_count {
        commitments.push(zero_commitment);
    }
    Ok(padded_count)
}

#[cfg(feature = "bulletproofs-backend")]
fn two_b(b_inf: u64) -> Result<u64> {
    b_inf.checked_mul(2).ok_or(AvsaError::InvalidRangeBound(
        "2B overflows the host representation",
    ))
}

#[cfg(feature = "bulletproofs-backend")]
fn bulletproofs_transcript(
    context: &RangeProofContext,
    chunk_index: usize,
    chunk_start: usize,
    chunk_end: usize,
    padded_count: usize,
) -> Transcript {
    let mut transcript = Transcript::new(BULLETPROOFS_TRANSCRIPT_LABEL);
    transcript.append_message(b"range-protocol-label", context.protocol_label);
    transcript.append_message(b"round-id", context.round_id.as_bytes());
    transcript.append_message(b"client-id", &context.client_id.to_le_bytes());
    transcript.append_message(b"dimension", &(context.dimension as u64).to_le_bytes());
    transcript.append_message(b"b-inf", &context.b_inf.to_le_bytes());
    transcript.append_message(b"bit-size", &(context.bit_size as u64).to_le_bytes());
    transcript.append_message(
        b"shifted-commitment-digest",
        &context.shifted_commitment_digest,
    );
    transcript.append_message(b"chunk-index", &(chunk_index as u64).to_le_bytes());
    transcript.append_message(b"chunk-start", &(chunk_start as u64).to_le_bytes());
    transcript.append_message(b"chunk-end", &(chunk_end as u64).to_le_bytes());
    transcript.append_message(b"chunk-padded-count", &(padded_count as u64).to_le_bytes());
    transcript
}

#[cfg(feature = "bulletproofs-backend")]
fn compress_points(commitments: &[RistrettoPoint]) -> Vec<CompressedRistretto> {
    commitments.iter().map(RistrettoPoint::compress).collect()
}

fn push_len_prefixed_hasher(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn finish_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}
