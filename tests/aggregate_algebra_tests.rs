use avsa_rs::commit::Generators;
use avsa_rs::mask::{aggregate_output, aggregate_plain_updates};
use avsa_rs::sim::round::build_honest_round;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

#[test]
fn aggregate_unmasking_matches_sum_of_admitted_updates() {
    let selected = vec![1, 2, 3, 4];
    let admitted = vec![1, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);
    signed_updates.insert(4, vec![2, 0, 1, -2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    let round = build_honest_round(
        "rid-aggregate",
        &selected,
        signed_updates,
        &generators,
        &mut rng,
    )
    .expect("honest round");

    let output =
        aggregate_output(&round.records, &round.graph, &admitted).expect("aggregate output");
    let plain_sum = aggregate_plain_updates(&round.updates, &admitted).expect("plain update sum");

    assert_eq!(output, plain_sum);
}
