use avsa_rs::audit::appeal::{verify_appeal, AppealOutcome};
use avsa_rs::audit::decision::{
    verify_accepted_decision, DecisionCertificate, DecisionEntry, DecisionStatus,
    PublicAuditContext, RejectReason,
};
use avsa_rs::commit::Generators;
use avsa_rs::proof::range::{
    signed_range_prove, MockRangeProof, MockRangeProofBackend, SignedRangePredicateVerifier,
    SignedRangeProof,
};
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
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    let round = build_honest_round(
        "rid-predicate-range",
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

fn range_proofs_for_round(
    round: &HonestRound,
    generators: &Generators,
) -> BTreeMap<u64, SignedRangeProof<MockRangeProof>> {
    round
        .records
        .iter()
        .map(|(client_id, record)| {
            let signed_update = round.signed_updates.get(client_id).expect("signed update");
            let blindings = round
                .commitment_blindings
                .get(client_id)
                .expect("commitment blindings");
            let proof = signed_range_prove::<MockRangeProofBackend>(
                round.round_id.as_str(),
                *client_id,
                &record.commitments,
                signed_update,
                blindings,
                3,
                3,
                generators,
            )
            .expect("signed range proof");
            (*client_id, proof)
        })
        .collect()
}

#[test]
fn accepted_decision_with_valid_range_predicate_accepts() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let proofs = range_proofs_for_round(&round, &generators);
    let verifier = SignedRangePredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        generators: &generators,
    };
    let record = round.records.get(&1).expect("record");
    let entry = cert.entry_for(1).expect("entry");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    verify_accepted_decision(&cert, entry, record, &verifier, &context)
        .expect("accepted decision verifies");
}

#[test]
fn accepted_decision_with_missing_range_proof_rejects() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let mut proofs = range_proofs_for_round(&round, &generators);
    proofs.remove(&1);
    let verifier = SignedRangePredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        generators: &generators,
    };
    let record = round.records.get(&1).expect("record");
    let entry = cert.entry_for(1).expect("entry");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(&cert, entry, record, &verifier, &context).is_err());
}

#[test]
fn accepted_decision_with_invalid_range_proof_rejects() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let mut proofs = range_proofs_for_round(&round, &generators);
    let proof = proofs.get_mut(&1).expect("proof");
    proof.backend_proof.shifted_values[0] += 1;
    let verifier = SignedRangePredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        generators: &generators,
    };
    let record = round.records.get(&1).expect("record");
    let entry = cert.entry_for(1).expect("entry");
    let context = PublicAuditContext {
        round_id: &round.round_id,
        selected_clients: &round.selected,
        generators: &generators,
    };

    assert!(verify_accepted_decision(&cert, entry, record, &verifier, &context).is_err());
}

#[test]
fn appeal_false_reject_with_valid_range_proof_succeeds() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(
        &round,
        DecisionStatus::Rejected(RejectReason::MissingRecord),
    );
    let proofs = range_proofs_for_round(&round, &generators);
    let verifier = SignedRangePredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        generators: &generators,
    };
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
        &verifier,
        &context,
    )
    .expect("appeal");

    assert_eq!(outcome, AppealOutcome::ServerFaultFalseReject);
}
