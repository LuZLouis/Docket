use avsa_rs::audit::decision::{
    verify_accepted_decision, AcceptAllPredicateVerifier, DecisionCertificate, DecisionEntry,
    DecisionStatus, PublicAuditContext, RejectReason,
};
use avsa_rs::commit::Generators;
use avsa_rs::receipt::{issue_receipt_for_record, verify_receipt, ReceiptStatus};
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, verify_record_membership, Transcript, TranscriptRoot};
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
    let mut rng = ChaCha20Rng::seed_from_u64(53);
    let round = build_honest_round(
        "rid-decision",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");
    (generators, round)
}

fn certificate_for_round(round: &HonestRound, status: DecisionStatus) -> DecisionCertificate {
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records).expect("transcript");
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
        round_id: round.round_id.clone(),
        transcript_root: transcript.root,
        entries,
    }
}

#[test]
fn transcript_root_is_deterministic_under_input_reordering() {
    let (_generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let mut reversed = records.clone();
    reversed.reverse();

    let root = Transcript::from_records(&records).expect("transcript").root;
    let reversed_root = Transcript::from_records(&reversed)
        .expect("reversed transcript")
        .root;

    assert_eq!(root, reversed_root);
}

#[test]
fn membership_proof_accepts_for_included_record() {
    let (_generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records).expect("transcript");
    let record = round.records.get(&1).expect("record");
    let proof = transcript.proof_for_client(1).expect("proof");

    verify_record_membership(
        &transcript.root,
        &round.round_id,
        1,
        &record_digest(record),
        &proof,
    )
    .expect("membership verifies");
}

#[test]
fn membership_proof_rejects_for_tampered_record_digest() {
    let (_generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records).expect("transcript");
    let proof = transcript.proof_for_client(1).expect("proof");
    let mut digest = proof.leaf_hash;
    digest.0[0] ^= 1;

    assert!(
        verify_record_membership(&transcript.root, &round.round_id, 1, &digest, &proof).is_err()
    );
}

#[test]
fn membership_proof_rejects_for_wrong_root() {
    let (_generators, round) = sample_round();
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records).expect("transcript");
    let record = round.records.get(&1).expect("record");
    let proof = transcript.proof_for_client(1).expect("proof");
    let mut wrong_root = transcript.root;
    wrong_root.0[0] ^= 1;

    assert!(verify_record_membership(
        &wrong_root,
        &round.round_id,
        1,
        &record_digest(record),
        &proof
    )
    .is_err());
}

#[test]
fn duplicate_client_ids_rejected_in_transcript_construction() {
    let (_generators, round) = sample_round();
    let record = round.records.get(&1).expect("record").clone();
    let duplicate_records = vec![record.clone(), record];

    assert!(Transcript::from_records(&duplicate_records).is_err());
}

#[test]
fn receipt_binds_round_client_and_record_digest() {
    let (_generators, round) = sample_round();
    let record = round.records.get(&1).expect("record");
    let receipt = issue_receipt_for_record(record, 1, 10);

    assert_eq!(
        verify_receipt(&receipt, record).expect("receipt"),
        ReceiptStatus::Timely
    );
}

#[test]
fn receipt_rejects_tampered_record() {
    let (_generators, round) = sample_round();
    let record = round.records.get(&1).expect("record");
    let mut receipt = issue_receipt_for_record(record, 1, 10);
    receipt.record_digest.0[0] ^= 1;

    assert!(verify_receipt(&receipt, record).is_err());
}

#[test]
fn verify_accepted_decision_accepts_valid_record() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let record = round.records.get(&1).expect("record");
    let entry = cert.entry_for(1).expect("entry");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    verify_accepted_decision(&cert, entry, record, &AcceptAllPredicateVerifier, &context)
        .expect("accepted decision verifies");
}

#[test]
fn verify_accepted_decision_rejects_record_not_in_root() {
    let (generators, round) = sample_round();
    let records_without_one: Vec<_> = round
        .records
        .iter()
        .filter_map(|(client, record)| (*client != 1).then(|| record.clone()))
        .collect();
    let transcript = Transcript::from_records(&records_without_one).expect("transcript");
    let record = round.records.get(&1).expect("record");
    let entry = DecisionEntry {
        round_id: round.round_id.clone(),
        client_id: 1,
        record_digest: record_digest(record),
        status: DecisionStatus::Accepted,
        membership_proof: None,
    };
    let cert = DecisionCertificate {
        round_id: round.round_id.clone(),
        transcript_root: transcript.root,
        entries: vec![entry],
    };
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(
        &cert,
        cert.entry_for(1).expect("entry"),
        record,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn verify_accepted_decision_rejects_tampered_record() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let mut record = round.records.get(&1).expect("record").clone();
    record.round_id.push_str("-tampered");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(
        &cert,
        cert.entry_for(1).expect("entry"),
        &record,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn verify_accepted_decision_rejects_invalid_submit_proof() {
    let (generators, round) = sample_round();
    let mut records: Vec<_> = round.records.values().cloned().collect();
    records[0].submission_proof.z_s.pop();
    let transcript = Transcript::from_records(&records).expect("transcript");
    let record = records
        .iter()
        .find(|record| record.client_id == 1)
        .expect("record");
    let entry = DecisionEntry {
        round_id: record.round_id.clone(),
        client_id: record.client_id,
        record_digest: record_digest(record),
        status: DecisionStatus::Accepted,
        membership_proof: transcript.proof_for_client(record.client_id),
    };
    let cert = DecisionCertificate {
        round_id: round.round_id.clone(),
        transcript_root: transcript.root,
        entries: vec![entry],
    };
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(
        &cert,
        cert.entry_for(1).expect("entry"),
        record,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn verify_accepted_decision_rejects_wrong_decision_root() {
    let (generators, round) = sample_round();
    let mut cert = certificate_for_round(&round, DecisionStatus::Accepted);
    cert.transcript_root = TranscriptRoot([7_u8; 32]);
    let record = round.records.get(&1).expect("record");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(
        &cert,
        cert.entry_for(1).expect("entry"),
        record,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn verify_accepted_decision_rejects_rejected_status() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(
        &round,
        DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("policy".into())),
    );
    let record = round.records.get(&1).expect("record");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(
        &cert,
        cert.entry_for(1).expect("entry"),
        record,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}
