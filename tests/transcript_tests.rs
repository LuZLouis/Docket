use avsa_rs::commit::Generators;
use avsa_rs::sim::round::build_honest_round;
use avsa_rs::transcript::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

#[test]
fn record_hash_root_is_deterministic() {
    let selected = vec![1, 2, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(29);
    let round = build_honest_round(
        "rid-transcript",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");

    let records: Vec<_> = round.records.values().cloned().collect();
    let mut shuffled = records.clone();
    shuffled.reverse();

    let transcript = Transcript::from_records(&records).expect("transcript");
    let transcript_again = Transcript::from_records(&records).expect("transcript again");
    let transcript_shuffled = Transcript::from_records(&shuffled).expect("transcript shuffled");

    assert_eq!(transcript.root, transcript_again.root);
    assert_eq!(transcript.root, transcript_shuffled.root);

    let proof = transcript.proof_for_client(2).expect("membership proof");
    assert!(Transcript::verify_membership(transcript.root, &proof).expect("verify membership"));
}
