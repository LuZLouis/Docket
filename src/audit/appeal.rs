use crate::audit::decision::{
    rejection_reason_is_publicly_valid, DecisionCertificate, DecisionEntry, DecisionStatus,
    PredicateVerifier, PublicAuditContext, RejectReason,
};
use crate::proof::submit::submit_verify_record;
use crate::receipt::{verify_receipt, verify_receipt_digest, ReceiptStatus, ServerReceipt};
use crate::record::ClientRecord;
use crate::transcript::{
    record_digest, verify_record_membership, verify_record_non_membership, NonMembershipProof,
    RecordDigest, TranscriptRoot,
};
use crate::{AvsaError, Result};

/// Appeal object skeleton for Algorithm 7.
#[derive(Clone, Debug, PartialEq)]
pub struct Appeal {
    pub receipt: ServerReceipt,
    pub record: Option<ClientRecord>,
    pub digest: RecordDigest,
    pub evidence_label: Option<String>,
}

/// Omission appeal evidence using only a receipt digest and public
/// non-inclusion under the authenticated digest log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmissionAppeal {
    pub receipt: ServerReceipt,
    pub round_id: String,
    pub client_id: crate::ClientId,
    pub digest: RecordDigest,
    pub transcript_root: TranscriptRoot,
    pub non_membership_proof: NonMembershipProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppealOutcome {
    NoServerFault,
    ServerFaultOmission,
    ServerFaultFalseReject,
    ClientFaultInvalidSubmission,
    RejectedWithValidReason,
}

pub fn verify_omission_appeal(appeal: &OmissionAppeal) -> Result<AppealOutcome> {
    let receipt_status = verify_receipt_digest(
        &appeal.receipt,
        &appeal.round_id,
        appeal.client_id,
        &appeal.digest,
    )?;
    if receipt_status == ReceiptStatus::Late {
        return Ok(AppealOutcome::NoServerFault);
    }
    verify_record_non_membership(
        &appeal.transcript_root,
        &appeal.round_id,
        appeal.client_id,
        &appeal.digest,
        &appeal.non_membership_proof,
    )?;
    Ok(AppealOutcome::ServerFaultOmission)
}

pub fn verify_appeal<P: PredicateVerifier>(
    receipt: &ServerReceipt,
    record: &ClientRecord,
    cert: &DecisionCertificate,
    decision_entry: Option<&DecisionEntry>,
    predicate_verifier: &P,
    context: &PublicAuditContext<'_>,
) -> Result<AppealOutcome> {
    if cert.round_id != context.round_id || record.round_id != context.round_id {
        return Err(AvsaError::InvalidDecisionCertificate);
    }

    let receipt_status = verify_receipt(receipt, record)?;
    if receipt_status == ReceiptStatus::Late {
        return Ok(AppealOutcome::NoServerFault);
    }

    let digest = record_digest(record);
    let included_in_root = match decision_entry {
        Some(entry) => {
            if !cert.contains_entry(entry) {
                return Err(AvsaError::InvalidDecisionEntry);
            }
            if entry.round_id != cert.round_id
                || entry.client_id != record.client_id
                || entry.record_digest != digest
            {
                return Err(AvsaError::DecisionRecordMismatch);
            }
            match &entry.membership_proof {
                Some(proof) => {
                    verify_record_membership(
                        &cert.transcript_root,
                        &cert.round_id,
                        record.client_id,
                        &digest,
                        proof,
                    )?;
                    true
                }
                None => false,
            }
        }
        None => false,
    };

    if !included_in_root {
        return Ok(AppealOutcome::ServerFaultOmission);
    }

    let submit_ok =
        submit_verify_record(record, context.selected_clients, context.generators).is_ok();
    let predicate_ok = submit_ok && predicate_verifier.verify_predicate(record).is_ok();

    let entry = decision_entry.ok_or(AvsaError::InvalidDecisionEntry)?;
    match &entry.status {
        DecisionStatus::Accepted => Ok(AppealOutcome::NoServerFault),
        DecisionStatus::Rejected(reason) => classify_rejection(
            reason,
            submit_ok,
            predicate_ok,
            receipt_status == ReceiptStatus::Timely,
            included_in_root,
        ),
    }
}

fn classify_rejection(
    reason: &RejectReason,
    submit_ok: bool,
    predicate_ok: bool,
    receipt_timely: bool,
    included_in_root: bool,
) -> Result<AppealOutcome> {
    let reason_ok = rejection_reason_is_publicly_valid(
        reason,
        submit_ok,
        predicate_ok,
        receipt_timely,
        included_in_root,
    );

    if submit_ok && predicate_ok && !reason_ok {
        return Ok(AppealOutcome::ServerFaultFalseReject);
    }

    if !submit_ok
        && matches!(
            reason,
            RejectReason::InvalidSubmitProof | RejectReason::InvalidMaskTag
        )
    {
        return Ok(AppealOutcome::ClientFaultInvalidSubmission);
    }

    if reason_ok {
        return Ok(AppealOutcome::RejectedWithValidReason);
    }

    Err(AvsaError::InvalidRejectReason)
}
