use crate::audit::decision::{
    verify_accepted_decision, DecisionCertificate, DecisionEntry, DecisionStatus,
    PredicateVerifier, PublicAuditContext,
};
use crate::audit::maskcert::{verify_mask_certificate, AdmittedSet, MaskCertificate};
use crate::record::ClientRecord;
use crate::transcript::TranscriptRoot;
use crate::vector::{add_vectors, sub_vectors, zero_vector, ScalarVector};
use crate::{AvsaError, ClientId, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Aggregate certificate from Algorithm 9.
#[derive(Clone, Debug, PartialEq)]
pub struct AggregateCertificate {
    pub round_id: String,
    pub transcript_root: TranscriptRoot,
    pub admitted_set: AdmittedSet,
    pub aggregate_output: ScalarVector,
    pub mask_certificate: MaskCertificate,
}

/// Backward-compatible alias for the Round 1 skeleton name.
pub type AggregateCert = AggregateCertificate;

pub fn verify_aggregate_certificate<P: PredicateVerifier>(
    cert: &AggregateCertificate,
    records: &[ClientRecord],
    decision_cert: &DecisionCertificate,
    decision_entries: &[DecisionEntry],
    predicate_verifier: &P,
    context: &PublicAuditContext<'_>,
) -> Result<()> {
    if cert.round_id != context.round_id
        || cert.mask_certificate.round_id != context.round_id
        || decision_cert.round_id != context.round_id
    {
        return Err(AvsaError::AggregateCertificateRoundMismatch);
    }
    if cert.transcript_root != decision_cert.transcript_root {
        return Err(AvsaError::AggregateCertificateRootMismatch);
    }
    if cert.admitted_set != cert.mask_certificate.admitted_set {
        return Err(AvsaError::AggregateDecisionSetMismatch);
    }

    let records_by_client = records_by_client(records)?;
    for record in records {
        if record.round_id != context.round_id {
            return Err(AvsaError::AggregateCertificateRoundMismatch);
        }
    }

    cert.admitted_set
        .validate_subset_of(context.selected_clients)
        .map_err(|_| AvsaError::InvalidAggregateCertificate)?;

    ensure_decision_set_matches(&cert.admitted_set, decision_entries)?;

    for client in &cert.admitted_set.clients {
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        let entry = decision_entries
            .iter()
            .find(|entry| {
                entry.client_id == *client && matches!(entry.status, DecisionStatus::Accepted)
            })
            .ok_or(AvsaError::MissingAcceptedDecision(*client))?;
        verify_accepted_decision(decision_cert, entry, record, predicate_verifier, context)?;
    }

    verify_mask_certificate(&cert.mask_certificate, &records_by_client, context)?;
    verify_output_equation(cert, &records_by_client)
}

fn ensure_decision_set_matches(
    admitted_set: &AdmittedSet,
    decision_entries: &[DecisionEntry],
) -> Result<()> {
    let admitted: BTreeSet<_> = admitted_set.clients.iter().copied().collect();
    if admitted.len() != admitted_set.clients.len() {
        return Err(AvsaError::InvalidAdmittedSet);
    }

    let mut accepted = BTreeSet::new();
    for entry in decision_entries {
        match &entry.status {
            DecisionStatus::Accepted => {
                accepted.insert(entry.client_id);
            }
            DecisionStatus::Rejected(_) => {
                if admitted.contains(&entry.client_id) {
                    return Err(AvsaError::RejectedClientInAggregate);
                }
            }
        }
    }

    for client in &admitted {
        if !accepted.contains(client) {
            return Err(AvsaError::MissingAcceptedDecision(*client));
        }
    }
    if accepted != admitted {
        return Err(AvsaError::AggregateDecisionSetMismatch);
    }
    Ok(())
}

fn verify_output_equation(
    cert: &AggregateCertificate,
    records_by_client: &BTreeMap<ClientId, ClientRecord>,
) -> Result<()> {
    let dim = cert.aggregate_output.len();
    if dim == 0 || cert.mask_certificate.aggregate_mask.len() != dim {
        return Err(AvsaError::InvalidAggregateOutput);
    }

    let mut masked_sum = zero_vector(dim);
    for client in &cert.admitted_set.clients {
        let record = records_by_client
            .get(client)
            .ok_or(AvsaError::MissingClient(*client))?;
        masked_sum = add_vectors(&masked_sum, &record.masked_update)?;
    }

    let expected = sub_vectors(&masked_sum, &cert.mask_certificate.aggregate_mask)?;
    if expected == cert.aggregate_output {
        Ok(())
    } else {
        Err(AvsaError::InvalidAggregateOutput)
    }
}

fn records_by_client(records: &[ClientRecord]) -> Result<BTreeMap<ClientId, ClientRecord>> {
    let mut out = BTreeMap::new();
    for record in records {
        if out.insert(record.client_id, record.clone()).is_some() {
            return Err(AvsaError::AggregateRecordSetMismatch);
        }
    }
    Ok(out)
}
