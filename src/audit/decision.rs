use crate::commit::Generators;
use crate::proof::submit::submit_verify_record;
use crate::record::ClientRecord;
use crate::transcript::{
    record_digest, verify_record_membership, MembershipProof, RecordDigest, TranscriptRoot,
};
use crate::{AvsaError, ClientId, Result};

/// Public context shared by decision and appeal verifiers.
#[derive(Clone, Copy, Debug)]
pub struct PublicAuditContext<'a> {
    pub round_id: &'a str,
    pub selected_clients: &'a [ClientId],
    pub generators: &'a Generators,
}

/// Placeholder predicate verifier interface for Round 3.
///
/// Real signed range, L2, and direction predicates are deferred. This trait
/// keeps Algorithms 6 and 7 wired to a public predicate decision point.
pub trait PredicateVerifier {
    fn verify_predicate(&self, record: &ClientRecord) -> Result<()>;
}

/// Test/helper predicate that accepts every record.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptAllPredicateVerifier;

impl PredicateVerifier for AcceptAllPredicateVerifier {
    fn verify_predicate(&self, _record: &ClientRecord) -> Result<()> {
        Ok(())
    }
}

/// Test/helper predicate that rejects one client id.
#[derive(Clone, Copy, Debug)]
pub struct RejectClientPredicateVerifier {
    pub client_id: ClientId,
}

impl PredicateVerifier for RejectClientPredicateVerifier {
    fn verify_predicate(&self, record: &ClientRecord) -> Result<()> {
        if record.client_id == self.client_id {
            Err(AvsaError::InvalidSubmitProof(
                "test predicate rejected the client",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionStatus {
    Accepted,
    Rejected(RejectReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    InvalidSubmitProof,
    InvalidDataPredicate,
    InvalidMaskTag,
    LateSubmission,
    DuplicateSubmission,
    MissingRecord,
    OtherPublicPolicy(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionEntry {
    pub round_id: String,
    pub client_id: ClientId,
    pub record_digest: RecordDigest,
    pub status: DecisionStatus,
    pub membership_proof: Option<MembershipProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionCertificate {
    pub round_id: String,
    pub transcript_root: TranscriptRoot,
    pub entries: Vec<DecisionEntry>,
}

impl DecisionCertificate {
    pub fn entry_for(&self, client_id: ClientId) -> Option<&DecisionEntry> {
        self.entries
            .iter()
            .find(|entry| entry.client_id == client_id)
    }

    pub fn contains_entry(&self, entry: &DecisionEntry) -> bool {
        self.entries.iter().any(|candidate| candidate == entry)
    }
}

pub fn verify_accepted_decision<P: PredicateVerifier>(
    cert: &DecisionCertificate,
    entry: &DecisionEntry,
    record: &ClientRecord,
    predicate_verifier: &P,
    context: &PublicAuditContext<'_>,
) -> Result<()> {
    if cert.round_id != context.round_id {
        return Err(AvsaError::InvalidDecisionCertificate);
    }
    if !cert.contains_entry(entry) {
        return Err(AvsaError::InvalidDecisionEntry);
    }
    if entry.round_id != cert.round_id || record.round_id != cert.round_id {
        return Err(AvsaError::InvalidDecisionEntry);
    }
    if entry.client_id != record.client_id {
        return Err(AvsaError::DecisionRecordMismatch);
    }
    if !matches!(entry.status, DecisionStatus::Accepted) {
        return Err(AvsaError::UnexpectedDecisionStatus);
    }

    let digest = record_digest(record);
    if entry.record_digest != digest {
        return Err(AvsaError::DecisionRecordMismatch);
    }

    let proof = entry
        .membership_proof
        .as_ref()
        .ok_or(AvsaError::MissingMembershipProof)?;
    verify_record_membership(
        &cert.transcript_root,
        &cert.round_id,
        record.client_id,
        &digest,
        proof,
    )?;

    submit_verify_record(record, context.selected_clients, context.generators)
        .map_err(|_| AvsaError::InvalidAcceptedDecision)?;
    predicate_verifier.verify_predicate(record)?;

    Ok(())
}

pub(crate) fn rejection_reason_is_publicly_valid(
    reason: &RejectReason,
    submit_ok: bool,
    predicate_ok: bool,
    receipt_timely: bool,
    included_in_root: bool,
) -> bool {
    match reason {
        RejectReason::InvalidSubmitProof | RejectReason::InvalidMaskTag => !submit_ok,
        RejectReason::InvalidDataPredicate => submit_ok && !predicate_ok,
        RejectReason::LateSubmission => !receipt_timely,
        RejectReason::DuplicateSubmission => true,
        RejectReason::MissingRecord => !included_in_root,
        RejectReason::OtherPublicPolicy(label) => !label.is_empty(),
    }
}
