#![cfg(feature = "bulletproofs-backend")]

use avsa_rs::audit::decision::{
    verify_accepted_decision, DecisionCertificate, DecisionEntry, DecisionStatus,
    PublicAuditContext,
};
use avsa_rs::commit::{Generators, PointVector};
use avsa_rs::proof::range::{
    shift_commitments, shift_signed_values, signed_range_prove, signed_range_verify,
    BulletproofsRangeBackend, BulletproofsRangeProof, RangeProofBackend, RangeProofContext,
    SignedRangePredicateVerifier, SignedRangeProof,
};
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use avsa_rs::transcript::{record_digest, Transcript};
use avsa_rs::vector::{encode_signed_vector, random_scalar_vector, ScalarVector};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

fn committed_signed_values(values: &[i64]) -> (Generators, ScalarVector, PointVector) {
    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(211);
    let encoded = encode_signed_vector(values);
    let blindings = random_scalar_vector(values.len(), &mut rng);
    let commitments = generators
        .commit_vector(&encoded, &blindings)
        .expect("commitments");
    (generators, blindings, commitments)
}

fn bulletproofs_signed_range_proof(
    round_id: &str,
    client_id: u64,
    signed_values: &[i64],
) -> (
    Generators,
    ScalarVector,
    PointVector,
    SignedRangeProof<BulletproofsRangeProof>,
) {
    let (generators, blindings, commitments) = committed_signed_values(signed_values);
    let proof = signed_range_prove::<BulletproofsRangeBackend>(
        round_id,
        client_id,
        &commitments,
        signed_values,
        &blindings,
        3,
        8,
        &generators,
    )
    .expect("Bulletproofs signed range proof");
    (generators, blindings, commitments, proof)
}

fn sample_round() -> (Generators, HonestRound) {
    let selected = vec![1, 2, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(213);
    let round = build_honest_round(
        "rid-bulletproofs-predicate",
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

fn bulletproofs_range_proofs_for_round(
    round: &HonestRound,
    generators: &Generators,
) -> BTreeMap<u64, SignedRangeProof<BulletproofsRangeProof>> {
    round
        .records
        .iter()
        .map(|(client_id, record)| {
            let signed_update = round.signed_updates.get(client_id).expect("signed update");
            let blindings = round
                .commitment_blindings
                .get(client_id)
                .expect("commitment blindings");
            let proof = signed_range_prove::<BulletproofsRangeBackend>(
                round.round_id.as_str(),
                *client_id,
                &record.commitments,
                signed_update,
                blindings,
                3,
                8,
                generators,
            )
            .expect("Bulletproofs signed range proof");
            (*client_id, proof)
        })
        .collect()
}

#[test]
fn bulletproofs_backend_accepts_valid_shifted_commitments() {
    let signed_values = vec![-2, 0, 3, 1];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let shifted_values = shift_signed_values(&signed_values, 3).expect("shifted values");
    let shifted_commitments =
        shift_commitments(&commitments, 3, &generators).expect("shifted commitments");
    let context = RangeProofContext::new("rid-bulletproofs", 7, 3, 8, &shifted_commitments)
        .expect("range context");

    let proof = BulletproofsRangeBackend::prove_range(
        &context,
        &shifted_commitments,
        &shifted_values,
        &blindings,
        8,
        &generators,
    )
    .expect("Bulletproofs prove");

    BulletproofsRangeBackend::verify_range(&context, &shifted_commitments, &proof, 8, &generators)
        .expect("Bulletproofs verify");
}

#[test]
fn signed_range_proof_with_bulletproofs_accepts_honest_vector() {
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 3, 1]);

    signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .expect("signed range verify");
}

#[test]
fn bulletproofs_backend_accepts_non_power_of_two_dimension() {
    let signed_values = vec![-2, 0, 3, 1, -1];
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs-non-pow2", 7, &signed_values);

    signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs-non-pow2",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .expect("non-power-of-two signed range verify");
}

#[test]
fn bulletproofs_backend_rejects_tampered_shifted_commitment() {
    let signed_values = vec![-2, 0, 3, 1];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);
    let shifted_values = shift_signed_values(&signed_values, 3).expect("shifted values");
    let mut shifted_commitments =
        shift_commitments(&commitments, 3, &generators).expect("shifted commitments");
    let context = RangeProofContext::new("rid-bulletproofs", 7, 3, 8, &shifted_commitments)
        .expect("range context");
    let proof = BulletproofsRangeBackend::prove_range(
        &context,
        &shifted_commitments,
        &shifted_values,
        &blindings,
        8,
        &generators,
    )
    .expect("Bulletproofs prove");
    shifted_commitments[0] = shifted_commitments[0] + generators.g;

    assert!(BulletproofsRangeBackend::verify_range(
        &context,
        &shifted_commitments,
        &proof,
        8,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_wrong_round_id() {
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 3, 1]);

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-other",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_wrong_client_id() {
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 3, 1]);

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        8,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_wrong_bound() {
    let (generators, _blindings, commitments, mut proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 2, 1]);
    proof.b_inf = 4;

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_wrong_bit_size() {
    let (generators, _blindings, commitments, mut proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 2, 1]);
    proof.bit_size = 16;

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments,
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_dimension_mismatch() {
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 2, 1]);

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments[..3],
        &proof,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_proof_commitment_substitution() {
    let first_values = vec![-2, 0, 2, 1];
    let second_values = vec![1, -1, 0, 2];
    let (generators, first_blindings, first_commitments) = committed_signed_values(&first_values);
    let first_shifted_values = shift_signed_values(&first_values, 3).expect("shifted values");
    let first_shifted_commitments =
        shift_commitments(&first_commitments, 3, &generators).expect("shifted commitments");
    let first_context =
        RangeProofContext::new("rid-bulletproofs", 7, 3, 8, &first_shifted_commitments)
            .expect("range context");
    let proof = BulletproofsRangeBackend::prove_range(
        &first_context,
        &first_shifted_commitments,
        &first_shifted_values,
        &first_blindings,
        8,
        &generators,
    )
    .expect("Bulletproofs prove");

    let (_unused_generators, _second_blindings, second_commitments) =
        committed_signed_values(&second_values);
    let second_shifted_commitments =
        shift_commitments(&second_commitments, 3, &generators).expect("shifted commitments");
    let second_context =
        RangeProofContext::new("rid-bulletproofs", 7, 3, 8, &second_shifted_commitments)
            .expect("range context");

    assert!(BulletproofsRangeBackend::verify_range(
        &second_context,
        &second_shifted_commitments,
        &proof,
        8,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_generator_mismatch() {
    let (generators, _blindings, commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 2, 1]);
    let wrong_generators = Generators {
        g: generators.g,
        h: generators.h + generators.g,
        k: generators.k,
    };

    assert!(signed_range_verify::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments,
        &proof,
        &wrong_generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_rejects_unsupported_bit_size() {
    let signed_values = vec![-2, 0, 2, 1];
    let (generators, blindings, commitments) = committed_signed_values(&signed_values);

    assert!(signed_range_prove::<BulletproofsRangeBackend>(
        "rid-bulletproofs",
        7,
        &commitments,
        &signed_values,
        &blindings,
        3,
        7,
        &generators,
    )
    .is_err());
}

#[test]
fn bulletproofs_backend_proof_object_has_no_witness_values() {
    let (_generators, _blindings, _commitments, proof) =
        bulletproofs_signed_range_proof("rid-bulletproofs", 7, &[-2, 0, 2, 1]);

    assert!(!proof.backend_proof.proof_chunks.is_empty());
    assert!(proof
        .backend_proof
        .proof_chunks
        .iter()
        .all(|chunk| !chunk.proof_bytes.is_empty()));
    let proof_debug = format!("{:?}", proof.backend_proof);
    assert!(!proof_debug.contains("shifted_values"));
    assert!(!proof_debug.contains("blindings"));
}

#[test]
fn predicate_verifier_accepts_valid_bulletproofs_range() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let proofs = bulletproofs_range_proofs_for_round(&round, &generators);
    let verifier = SignedRangePredicateVerifier::<BulletproofsRangeBackend> {
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
fn predicate_verifier_rejects_invalid_bulletproofs_range() {
    let (generators, round) = sample_round();
    let cert = certificate_for_round(&round, DecisionStatus::Accepted);
    let mut proofs = bulletproofs_range_proofs_for_round(&round, &generators);
    let proof = proofs.get_mut(&1).expect("proof");
    proof.shifted_commitments[0] = proof.shifted_commitments[0] + generators.g;
    let verifier = SignedRangePredicateVerifier::<BulletproofsRangeBackend> {
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
