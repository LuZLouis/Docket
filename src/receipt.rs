use crate::record::ClientRecord;
use crate::transcript::{record_digest, RecordDigest};
use crate::{AvsaError, ClientId, Result};

/// Round 3 server receipt.
///
/// Signatures are intentionally a placeholder in this round. The receipt binds
/// the round, client, record digest, and a deterministic timeliness window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerReceipt {
    pub round_id: String,
    pub client_id: ClientId,
    pub record_digest: RecordDigest,
    pub receive_seq: u64,
    pub deadline_seq: u64,
    pub server_signature: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    Timely,
    Late,
}

pub fn issue_receipt(
    round_id: impl Into<String>,
    client_id: ClientId,
    record_digest: RecordDigest,
    receive_seq: u64,
    deadline_seq: u64,
) -> ServerReceipt {
    ServerReceipt {
        round_id: round_id.into(),
        client_id,
        record_digest,
        receive_seq,
        deadline_seq,
        server_signature: None,
    }
}

pub fn issue_receipt_for_record(
    record: &ClientRecord,
    receive_seq: u64,
    deadline_seq: u64,
) -> ServerReceipt {
    issue_receipt(
        record.round_id.clone(),
        record.client_id,
        record_digest(record),
        receive_seq,
        deadline_seq,
    )
}

pub fn verify_receipt(receipt: &ServerReceipt, record: &ClientRecord) -> Result<ReceiptStatus> {
    if receipt.round_id != record.round_id || receipt.client_id != record.client_id {
        return Err(AvsaError::ReceiptRecordMismatch);
    }
    if receipt.record_digest != record_digest(record) {
        return Err(AvsaError::ReceiptRecordMismatch);
    }
    if receipt.receive_seq <= receipt.deadline_seq {
        Ok(ReceiptStatus::Timely)
    } else {
        Ok(ReceiptStatus::Late)
    }
}

pub fn verify_receipt_digest(
    receipt: &ServerReceipt,
    round_id: &str,
    client_id: ClientId,
    record_digest: &RecordDigest,
) -> Result<ReceiptStatus> {
    if receipt.round_id != round_id
        || receipt.client_id != client_id
        || &receipt.record_digest != record_digest
    {
        return Err(AvsaError::ReceiptRecordMismatch);
    }
    if receipt.receive_seq <= receipt.deadline_seq {
        Ok(ReceiptStatus::Timely)
    } else {
        Ok(ReceiptStatus::Late)
    }
}
