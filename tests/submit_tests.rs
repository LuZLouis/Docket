use avsa_rs::commit::Generators;
use avsa_rs::proof::submit::{challenge_for_record, submit_verify_record};
use avsa_rs::record::ClientRecord;
use avsa_rs::sim::round::{build_honest_round, HonestRound};
use curve25519_dalek::scalar::Scalar;
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
    let mut rng = ChaCha20Rng::seed_from_u64(41);
    let round = build_honest_round(
        "rid-submit",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");
    (generators, round)
}

fn first_record(round: &HonestRound) -> ClientRecord {
    round.records.get(&1).expect("client 1 record").clone()
}

#[test]
fn honest_submit_proof_accepts() {
    let (generators, round) = sample_round();
    for record in round.records.values() {
        submit_verify_record(record, &round.selected, &generators).expect("honest submit proof");
    }
}

#[test]
fn tampered_u_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.masked_update[0] = record.masked_update[0] + Scalar::from(1_u64);

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn tampered_commitment_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.commitments[0] = record.commitments[0] + generators.g;

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn tampered_mask_tag_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.submitted_tag += generators.k;

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn tampered_self_tag_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.aux.self_tag += generators.k;

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn tampered_pair_tag_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    let peer = record
        .aux
        .pair_tags
        .keys()
        .next()
        .copied()
        .expect("peer tag");
    let tag = record.aux.pair_tags.get_mut(&peer).expect("pair tag");
    *tag += generators.k;

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn wrong_round_id_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.round_id.push_str("-wrong");

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn wrong_peer_order_or_selected_set_rejects() {
    let (generators, round) = sample_round();
    let record = first_record(&round);
    let wrong_order = vec![1, 3, 2];

    assert!(submit_verify_record(&record, &wrong_order, &generators).is_err());
}

#[test]
fn proof_dimension_mismatch_rejects() {
    let (generators, round) = sample_round();
    let mut record = first_record(&round);
    record.submission_proof.z_s.pop();

    assert!(submit_verify_record(&record, &round.selected, &generators).is_err());
}

#[test]
fn challenge_is_deterministic_for_same_transcript() {
    let (generators, round) = sample_round();
    let record = first_record(&round);

    let first = challenge_for_record(&record, &round.selected, &generators).expect("challenge");
    let second =
        challenge_for_record(&record, &round.selected, &generators).expect("challenge again");

    assert_eq!(first, second);
}
