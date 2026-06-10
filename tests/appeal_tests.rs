use avsa_rs::audit::appeal::{verify_appeal, AppealOutcome};
use avsa_rs::audit::decision::{
    AcceptAllPredicateVerifier, DecisionCertificate, DecisionEntry, DecisionStatus,
    PublicAuditContext, RejectReason,
};
use avsa_rs::commit::Generators;
use avsa_rs::receipt::issue_receipt_for_record;
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, Transcript};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(67);
    let round = build_honest_round(
        "rid-appeal",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");
    (generators, round)
}

fn certificate_for_records(
    round_id: &str,
    records: &[avsa_rs::record::ClientRecord],
    status: DecisionStatus,
) -> DecisionCertificate {
    let transcript = Transcript::from_records(records).expect("transcript");
    let entries = records
        .iter()
        .map(|record| DecisionEntry {
            round_id: record.round_id.clone(),
            client_id: record.client_id,
            record_digest: record_digest(record),
            status: status.clone(),
            membership_proof: transcript.proof_for_client(record.client_id),
        })
        .collect();
    DecisionCertificate {
        round_id: round_id.to_string(),
        transcript_root: transcript.root,
        entries,
    }
}

#[test]
fn timely_record_omitted_from_root_triggers_server_fault_omission() {
    let (generators, round) = sample_round();
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);
    let records_without_one: Vec<_> = round
        .records
        .iter()
        .filter_map(|(client, record)| (*client != 1).then(|| record.clone()))
        .collect();
    let cert = certificate_for_records(
        &round.round_id,
        &records_without_one,
        DecisionStatus::Accepted,
    );
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        record,
        &cert,
        None,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::ServerFaultOmission);
}

#[test]
fn included_valid_record_rejected_without_valid_reason_triggers_false_reject() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let cert = certificate_for_records(
        &round.round_id,
        &records,
        DecisionStatus::Rejected(RejectReason::MissingRecord),
    );
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::ServerFaultFalseReject);
}

#[test]
fn included_valid_record_rejected_with_valid_public_reason_is_no_false_reject() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let cert = certificate_for_records(
        &round.round_id,
        &records,
        DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("quota".into())),
    );
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::RejectedWithValidReason);
}

#[test]
fn invalid_submit_record_rejected_for_invalid_submit_is_not_server_fault() {
    let (generators, round) = sample_round();
    let mut records: Vec<_> = round.records.values().cloned().collect();
    let tampered = records
        .iter_mut()
        .find(|record| record.client_id == 1)
        .expect("record");
    tampered.submission_proof.z_s.pop();
    let record = tampered.clone();
    let receipt = issue_receipt_for_record(&record, 1, 10);
    let cert = certificate_for_records(
        &round.round_id,
        &records,
        DecisionStatus::Rejected(RejectReason::InvalidSubmitProof),
    );
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        &record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::ClientFaultInvalidSubmission);
}

#[test]
fn late_receipt_rejection_is_not_server_fault() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let cert = certificate_for_records(
        &round.round_id,
        &records,
        DecisionStatus::Rejected(RejectReason::LateSubmission),
    );
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 11, 10);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::NoServerFault);
}

#[test]
fn tampered_receipt_rejects_or_does_not_create_server_fault() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let cert = certificate_for_records(&round.round_id, &records, DecisionStatus::Accepted);
    let record = round.records.get(&1).expect("record");
    let mut receipt = issue_receipt_for_record(record, 1, 10);
    receipt.record_digest.0[0] ^= 1;
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn appeal_rejects_record_digest_mismatch() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let mut cert = certificate_for_records(&round.round_id, &records, DecisionStatus::Accepted);
    let entry = cert
        .entries
        .iter_mut()
        .find(|entry| entry.client_id == 1)
        .expect("entry");
    entry.record_digest.0[0] ^= 1;
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn accepted_valid_record_has_no_server_fault() {
    let (generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let cert = certificate_for_records(&round.round_id, &records, DecisionStatus::Accepted);
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    let outcome = verify_appeal(
        &receipt,
        record,
        &cert,
        cert.entry_for(1),
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::NoServerFault);
}
