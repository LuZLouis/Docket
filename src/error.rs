use crate::ClientId;
use thiserror::Error;

/// Error type used by the AVSA reference skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AvsaError {
    #[error("invalid AVSA parameters: {0}")]
    InvalidParams(String),

    #[error("invalid bound: {0}")]
    InvalidBound(String),

    #[error("empty input: {0}")]
    EmptyInput(&'static str),

    #[error("dimension mismatch in {context}: expected {expected}, got {actual}")]
    DimensionMismatch {
        context: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("duplicate client id {0}")]
    DuplicateClient(ClientId),

    #[error("unknown client id {0}")]
    UnknownClient(ClientId),

    #[error("missing client id {0}")]
    MissingClient(ClientId),

    #[error("missing pairwise mask for clients {left} and {right}")]
    MissingPair { left: ClientId, right: ClientId },

    #[error("missing pairwise tag for client {client} and peer {peer}")]
    MissingPairTag { client: ClientId, peer: ClientId },

    #[error("missing peer tag for client {client} and peer {peer}")]
    MissingPeerTag { client: ClientId, peer: ClientId },

    #[error("invalid peer order: {0}")]
    InvalidPeerOrder(String),

    #[error("invalid submission proof: {0}")]
    InvalidSubmitProof(&'static str),

    #[error("invalid mask tag equation")]
    InvalidMaskTagEquation,

    #[error("invalid Fiat-Shamir transcript: {0}")]
    InvalidTranscript(String),

    #[error("invalid transcript root")]
    InvalidTranscriptRoot,

    #[error("invalid membership proof")]
    InvalidMembershipProof,

    #[error("missing membership proof")]
    MissingMembershipProof,

    #[error("duplicate transcript record for client id {0}")]
    DuplicateTranscriptRecord(ClientId),

    #[error("invalid record digest")]
    InvalidRecordDigest,

    #[error("invalid receipt")]
    InvalidReceipt,

    #[error("receipt does not match record")]
    ReceiptRecordMismatch,

    #[error("receipt is late")]
    LateReceipt,

    #[error("invalid decision certificate")]
    InvalidDecisionCertificate,

    #[error("invalid decision entry")]
    InvalidDecisionEntry,

    #[error("decision root mismatch")]
    DecisionRootMismatch,

    #[error("decision record mismatch")]
    DecisionRecordMismatch,

    #[error("unexpected decision status")]
    UnexpectedDecisionStatus,

    #[error("invalid accepted decision")]
    InvalidAcceptedDecision,

    #[error("invalid reject reason")]
    InvalidRejectReason,

    #[error("server fault: omission")]
    ServerFaultOmission,

    #[error("server fault: false reject")]
    ServerFaultFalseReject,

    #[error("invalid admitted set")]
    InvalidAdmittedSet,

    #[error("admitted set is not a subset of selected clients")]
    AdmittedSetNotSubsetOfSelected,

    #[error("duplicate admitted client id {0}")]
    DuplicateAdmittedClient(ClientId),

    #[error("invalid mask certificate")]
    InvalidMaskCertificate,

    #[error("mask certificate round mismatch")]
    MaskCertificateRoundMismatch,

    #[error("mask certificate selected set mismatch")]
    MaskCertificateSelectedSetMismatch,

    #[error("missing self-mask opening for client id {0}")]
    MissingSelfOpening(ClientId),

    #[error("extra self-mask opening for client id {0}")]
    ExtraSelfOpening(ClientId),

    #[error("missing pair-mask opening for clients {admitted} and {other}")]
    MissingPairOpening { admitted: ClientId, other: ClientId },

    #[error("extra pair-mask opening for clients {admitted} and {other}")]
    ExtraPairOpening { admitted: ClientId, other: ClientId },

    #[error("invalid self-mask opening")]
    InvalidSelfMaskOpening,

    #[error("invalid pair-mask opening")]
    InvalidPairMaskOpening,

    #[error("invalid mask-opening dimension")]
    InvalidMaskOpeningDimension,

    #[error("invalid aggregate mask")]
    InvalidAggregateMask,

    #[error("invalid aggregate tag relation")]
    InvalidAggregateTagRelation,

    #[error("invalid aggregate certificate")]
    InvalidAggregateCertificate,

    #[error("aggregate certificate round mismatch")]
    AggregateCertificateRoundMismatch,

    #[error("aggregate certificate root mismatch")]
    AggregateCertificateRootMismatch,

    #[error("aggregate admitted set does not match accepted decisions")]
    AggregateDecisionSetMismatch,

    #[error("aggregate record set mismatch")]
    AggregateRecordSetMismatch,

    #[error("rejected client appears in aggregate")]
    RejectedClientInAggregate,

    #[error("missing accepted decision for client id {0}")]
    MissingAcceptedDecision(ClientId),

    #[error("invalid aggregate output")]
    InvalidAggregateOutput,

    #[error("invalid range proof: {0}")]
    InvalidRangeProof(&'static str),

    #[error("invalid range proof context: {0}")]
    InvalidRangeProofContext(&'static str),

    #[error("invalid range proof dimension")]
    InvalidRangeProofDimension,

    #[error("invalid range bound: {0}")]
    InvalidRangeBound(&'static str),

    #[error("invalid range bit size: {0}")]
    InvalidRangeBitSize(&'static str),

    #[error("unsupported range bit size {0}")]
    UnsupportedRangeBitSize(usize),

    #[error("signed value is outside the active range bound")]
    SignedValueOutOfRange,

    #[error("invalid shifted range commitment")]
    InvalidShiftedCommitment,

    #[error("invalid range commitment")]
    InvalidRangeCommitment,

    #[error("range proof backend error: {0}")]
    RangeProofBackendError(String),

    #[error("Bulletproofs backend error: {0}")]
    BulletproofsBackendError(String),

    #[error("range proof generator mismatch")]
    GeneratorMismatch,

    #[error("missing data proof for client id {0}")]
    MissingDataProof(ClientId),

    #[error("invalid predicate proof")]
    InvalidPredicateProof,

    #[error("invalid L2 proof: {0}")]
    InvalidL2Proof(&'static str),

    #[error("invalid L2 statement: {0}")]
    InvalidL2Statement(&'static str),

    #[error("invalid L2 witness: {0}")]
    InvalidL2Witness(&'static str),

    #[error("invalid L2 dimension")]
    InvalidL2Dimension,

    #[error("invalid L2 bound: {0}")]
    InvalidL2Bound(&'static str),

    #[error("L2 norm overflow")]
    L2NormOverflow,

    #[error("L2 slack underflow")]
    L2SlackUnderflow,

    #[error("invalid L2 transcript")]
    InvalidL2Transcript,

    #[error("invalid L2 quadratic relation")]
    InvalidQuadraticRelation,

    #[error("invalid L2 norm commitment")]
    InvalidNormCommitment,

    #[error("invalid L2 slack commitment")]
    InvalidSlackCommitment,

    #[error("invalid L2 range proof")]
    InvalidL2RangeProof,

    #[error("invalid benchmark config: {0}")]
    InvalidBenchConfig(String),

    #[error("unsupported benchmark backend: {0}")]
    UnsupportedBenchBackend(String),

    #[error("unsupported benchmark preset: {0}")]
    UnsupportedBenchPreset(String),

    #[error("benchmark generation failed: {0}")]
    BenchGenerationFailed(String),

    #[error("benchmark operation failed: {0}")]
    BenchOperationFailed(String),

    #[error("benchmark correctness failed: {0}")]
    BenchCorrectnessFailed(String),

    #[error("benchmark serialization failed: {0}")]
    BenchSerializationFailed(String),

    #[error("benchmark CSV write failed: {0}")]
    BenchCsvWriteFailed(String),

    #[error("boundary pair set does not match A x (D_s \\ A)")]
    BoundarySetMismatch,

    #[error("transcript error: {0}")]
    Transcript(String),
}

pub type Result<T> = std::result::Result<T, AvsaError>;
