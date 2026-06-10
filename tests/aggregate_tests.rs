use avsa_rs::audit::aggregate::{verify_aggregate_certificate, AggregateCertificate};
use avsa_rs::audit::decision::{
    AcceptAllPredicateVerifier, DecisionCertificate, DecisionEntry, DecisionStatus,
    PublicAuditContext, RejectReason,
};
use avsa_rs::audit::maskcert::{AdmittedSet, MaskCertificate, PairMaskOpening, SelfMaskOpening};
use avsa_rs::commit::Generators;
use avsa_rs::mask::required_boundary_pairs;
use avsa_rs::record::ClientRecord;
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, Transcript, TranscriptRoot};
use avsa_rs::vector::{add_vectors, sub_vectors, zero_vector, ScalarVector};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3, 4];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);
    signed_updates.insert(4, vec![2, 0, 1, -2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(83);
    let round = build_honest_round(
        "rid-aggregate-cert",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");
    (generators, round)
}

fn honest_mask_certificate(round: &HonestRound, admitted: &[u64]) -> MaskCertificate {
    let self_openings = admitted
        .iter()
        .map(|client| SelfMaskOpening {
            client_id: *client,
            mask: round.graph.self_mask(*client).expect("self mask").clone(),
        })
        .collect();
    let pair_openings = required_boundary_pairs(&round.selected, admitted)
        .expect("boundary pairs")
        .into_iter()
        .map(|(admitted_client, other_client)| PairMaskOpening {
            admitted_client,
            other_client,
            mask: round
                .graph
                .pair_mask(admitted_client, other_client)
                .expect("pair mask")
                .clone(),
        })
        .collect();

    MaskCertificate {
        round_id: round.round_id.clone(),
        selected_clients: round.selected.clone(),
        admitted_set: AdmittedSet::new(admitted.to_vec()).expect("admitted set"),
        aggregate_mask: round
            .graph
            .aggregate_mask(admitted)
            .expect("aggregate mask"),
        self_openings,
        pair_openings,
    }
}

fn output_from_records(
    records: &BTreeMap<u64, ClientRecord>,
    admitted: &[u64],
    aggregate_mask: &[Scalar],
) -> ScalarVector {
    let mut sum = zero_vector(aggregate_mask.len());
    for client in admitted {
        sum = add_vectors(&sum, &records.get(client).expect("record").masked_update)
            .expect("masked sum");
    }
    sub_vectors(&sum, aggregate_mask).expect("aggregate output")
}

fn decision_certificate(
    round: &HonestRound,
    admitted: &[u64],
) -> (DecisionCertificate, Vec<DecisionEntry>) {
    let records: Vec<_> = round.records.values().cloned().collect();
    let transcript = Transcript::from_records(&records).expect("transcript");
    let admitted_set: std::collections::BTreeSet<_> = admitted.iter().copied().collect();
    let entries: Vec<_> = records
        .iter()
        .map(|record| DecisionEntry {
            round_id: record.round_id.clone(),
            client_id: record.client_id,
            record_digest: record_digest(record),
            status: if admitted_set.contains(&record.client_id) {
                DecisionStatus::Accepted
            } else {
                DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("not-admitted".into()))
            },
            membership_proof: transcript.proof_for_client(record.client_id),
        })
        .collect();
    (
        DecisionCertificate {
            round_id: round.round_id.clone(),
            transcript_root: transcript.root,
            entries: entries.clone(),
        },
        entries,
    )
}

fn honest_aggregate_fixture(
    admitted: &[u64],
) -> (
    Generators,
    HonestRound,
    AggregateCertificate,
    DecisionCertificate,
    Vec<DecisionEntry>,
) {
    let (generators, round) = sample_round();
    let mask_certificate = honest_mask_certificate(&round, admitted);
    let records = round.records.clone();
    let output = output_from_records(&records, admitted, &mask_certificate.aggregate_mask);
    let (decision_cert, decision_entries) = decision_certificate(&round, admitted);
    let aggregate_cert = AggregateCertificate {
        round_id: round.round_id.clone(),
        transcript_root: decision_cert.transcript_root,
        admitted_set: AdmittedSet::new(admitted.to_vec()).expect("admitted set"),
        aggregate_output: output,
        mask_certificate,
    };
    (
        generators,
        round,
        aggregate_cert,
        decision_cert,
        decision_entries,
    )
}

fn records_vec(round: &HonestRound) -> Vec<ClientRecord> {
    round.records.values().cloned().collect()
}

#[test]
fn verify_aggregate_certificate_accepts_honest_aggregate() {
    let (generators, round, cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .expect("honest aggregate certificate");
}

#[test]
fn wrong_aggregate_output_rejects() {
    let (generators, round, mut cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    cert.aggregate_output[0] = cert.aggregate_output[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn tampered_admitted_record_rejects() {
    let (generators, round, cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    let mut records = records_vec(&round);
    let record = records
        .iter_mut()
        .find(|record| record.client_id == 1)
        .expect("record");
    record.masked_update[0] = record.masked_update[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records,
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn admitted_set_not_matching_accepted_decisions_rejects() {
    let (generators, round, cert, decision_cert, _decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    let (_wrong_cert, wrong_entries) = decision_certificate(&round, &[1]);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &wrong_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn rejected_client_in_aggregate_rejects() {
    let (generators, round, cert, decision_cert, mut decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    let entry = decision_entries
        .iter_mut()
        .find(|entry| entry.client_id == 3)
        .expect("entry");
    entry.status = DecisionStatus::Rejected(RejectReason::OtherPublicPolicy("reject".into()));
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn missing_accepted_decision_rejects() {
    let (generators, round, cert, decision_cert, mut decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    decision_entries.retain(|entry| entry.client_id != 3);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn wrong_transcript_root_rejects() {
    let (generators, round, mut cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    cert.transcript_root = TranscriptRoot([9_u8; 32]);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn wrong_mask_certificate_rejects() {
    let (generators, round, mut cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    cert.mask_certificate.self_openings[0].mask[0] =
        cert.mask_certificate.self_openings[0].mask[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn changed_admitted_set_rejects() {
    let (generators, round, mut cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    cert.admitted_set = AdmittedSet::new(vec![1]).expect("admitted set");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}

#[test]
fn changed_aggregate_mask_rejects() {
    let (generators, round, mut cert, decision_cert, decision_entries) =
        honest_aggregate_fixture(&[1, 3]);
    cert.mask_certificate.aggregate_mask[0] =
        cert.mask_certificate.aggregate_mask[0] + Scalar::from(1_u64);
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_aggregate_certificate(
        &cert,
        &records_vec(&round),
        &decision_cert,
        &decision_entries,
        &AcceptAllPredicateVerifier,
        &context,
    )
    .is_err());
}
