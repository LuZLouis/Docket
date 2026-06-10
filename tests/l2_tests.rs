use avsa_rs::audit::decision::{
    verify_accepted_decision, DecisionCertificate, DecisionEntry, DecisionStatus,
    PublicAuditContext,
};
use avsa_rs::commit::{Generators, PointVector};
use avsa_rs::proof::l2::{
    checked_l2_norm_sq, l2_prove, l2_verify, L2PredicateVerifier, L2Proof, L2Statement, L2Witness,
};
use avsa_rs::proof::range::{MockRangeProof, MockRangeProofBackend};
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, Transcript};
use avsa_rs::vector::{encode_signed_vector, random_scalar_vector, ScalarVector};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

fn committed_signed_values(values: &[i64]) -> (Generators, ScalarVector, PointVector) {
    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(307);
    let encoded = encode_signed_vector(values);
    let blindings = random_scalar_vector(values.len(), &mut rng);
    let commitments = generators
        .commit_vector(&encoded, &blindings)
        .expect("commitments");
    (generators, blindings, commitments)
}

fn l2_mock_proof(
    rid: &str,
    client_id: u64,
    values: &[i64],
    b2_sq: u64,
    bit_size: usize,
) -> (
    Generators,
    ScalarVector,
    PointVector,
    L2Proof<MockRangeProof>,
) {
    let (generators, blindings, commitments) = committed_signed_values(values);
    let statement = L2Statement {
        rid,
        client_id,
        commitments: &commitments,
        b2_sq,
        bit_size,
    };
    let witness = L2Witness {
        values,
        blindings: &blindings,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(311);
    let proof = l2_prove::<MockRangeProofBackend, _>(&statement, &witness, &generators, &mut rng)
        .expect("L2 proof");
    (generators, blindings, commitments, proof)
}

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(313);
    let round = build_honest_round(
        "rid-l2-predicate",
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

fn l2_proofs_for_round(
    round: &HonestRound,
    generators: &Generators,
) -> BTreeMap<u64, L2Proof<MockRangeProof>> {
    round
        .records
        .iter()
        .map(|(client_id, record)| {
            let values = round.signed_updates.get(client_id).expect("signed update");
            let blindings = round
                .commitment_blindings
                .get(client_id)
                .expect("commitment blindings");
            let statement = L2Statement {
                rid: round.round_id.as_str(),
                client_id: *client_id,
                commitments: &record.commitments,
                b2_sq: 10,
                bit_size: 5,
            };
            let witness = L2Witness { values, blindings };
            let mut rng = ChaCha20Rng::seed_from_u64(317 + *client_id);
            let proof =
                l2_prove::<MockRangeProofBackend, _>(&statement, &witness, generators, &mut rng)
                    .expect("L2 proof");
            (*client_id, proof)
        })
        .collect()
}

#[test]
fn l2_proof_accepts_honest_vector_under_bound() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).expect("L2 verifies");
}

#[test]
fn l2_proof_rejects_vector_over_bound() {
    let values = vec![3, 3];
    let (generators, blindings, commitments) = committed_signed_values(&values);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };
    let witness = L2Witness {
        values: &values,
        blindings: &blindings,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(319);

    assert!(
        l2_prove::<MockRangeProofBackend, _>(&statement, &witness, &generators, &mut rng,).is_err()
    );
}

#[test]
fn l2_proof_rejects_tampered_input_commitment() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, mut commitments, proof) =
        l2_mock_proof("rid-l2", 7, &values, 10, 5);
    commitments[0] = commitments[0] + generators.g;
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_wrong_round_id() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-other",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_wrong_client_id() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 8,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_wrong_bound() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 11,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_wrong_bit_size() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 6,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_dimension_mismatch() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, proof) = l2_mock_proof("rid-l2", 7, &values, 10, 5);
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments[..2],
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_tampered_norm_or_slack_commitment() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, mut proof) =
        l2_mock_proof("rid-l2", 7, &values, 10, 5);
    proof.slack_commitment = proof.slack_commitment + generators.g;
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_tampered_quadratic_message() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, mut proof) =
        l2_mock_proof("rid-l2", 7, &values, 10, 5);
    proof.c_plus = proof.c_plus + generators.g;
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_proof_rejects_tampered_backend_range_proof() {
    let values = vec![1, -2, 2];
    let (generators, _blindings, commitments, mut proof) =
        l2_mock_proof("rid-l2", 7, &values, 10, 5);
    proof.range_proof.shifted_values[0] += 1;
    let statement = L2Statement {
        rid: "rid-l2",
        client_id: 7,
        commitments: &commitments,
        b2_sq: 10,
        bit_size: 5,
    };

    assert!(l2_verify::<MockRangeProofBackend>(&statement, &proof, &generators).is_err());
}

#[test]
fn l2_norm_checked_arithmetic_rejects_overflow() {
    let values = vec![i64::MAX, i64::MAX, i64::MAX, i64::MAX, i64::MAX];

    assert!(checked_l2_norm_sq(&values).is_err());
}

#[test]
fn predicate_verifier_accepts_valid_l2_proof() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let proofs = l2_proofs_for_round(&round, &generators);
    let verifier = L2PredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        b2_sq: 10,
        bit_size: 5,
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
fn predicate_verifier_rejects_invalid_l2_proof() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let mut proofs = l2_proofs_for_round(&round, &generators);
    let proof = proofs.get_mut(&1).expect("proof");
    proof.z[0] = proof.z[0] + Scalar::from(1_u64);
    let verifier = L2PredicateVerifier::<MockRangeProofBackend> {
        proofs_by_client: &proofs,
        b2_sq: 10,
        bit_size: 5,
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
