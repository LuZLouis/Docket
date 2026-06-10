use avsa_rs::commit::Generators;
use avsa_rs::mask::{
    boundary_pairs_match, required_boundary_pairs, submitted_tag_equation_holds, PairwiseMaskGraph,
};
use avsa_rs::sim::round::build_honest_round;
use avsa_rs::vector::{add_vectors, zero_vector};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

#[test]
fn pairwise_masks_cancel_for_all_selected_clients() {
    let selected = vec![1, 2, 3, 4];
    let dim = 8;
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let graph = PairwiseMaskGraph::sample_complete(&selected, dim, &mut rng).expect("graph");

    let mut pairwise_sum = zero_vector(dim);
    for client in &selected {
        pairwise_sum = add_vectors(
            &pairwise_sum,
            &graph
                .pairwise_contribution(*client)
                .expect("pairwise contribution"),
        )
        .expect("sum pairwise contributions");
    }

    assert_eq!(pairwise_sum, zero_vector(dim));
}

#[test]
fn boundary_pairs_equal_a_cross_ds_minus_a() {
    let selected = vec![1, 2, 3, 4];
    let admitted = vec![1, 3];
    let pairs = required_boundary_pairs(&selected, &admitted).expect("boundary pairs");
    assert_eq!(pairs, vec![(1, 2), (1, 4), (3, 2), (3, 4)]);
}

#[test]
fn wrong_boundary_pair_set_is_detectable_by_helper() {
    let selected = vec![1, 2, 3, 4];
    let admitted = vec![1, 3];
    let correct = required_boundary_pairs(&selected, &admitted).expect("boundary pairs");
    assert!(boundary_pairs_match(&selected, &admitted, &correct).expect("match helper"));

    let wrong = vec![(1, 2), (1, 4), (3, 2)];
    assert!(!boundary_pairs_match(&selected, &admitted, &wrong).expect("match helper"));
}

#[test]
fn tag_equation_holds_for_each_client() {
    let selected = vec![1, 2, 3];
    let mut signed_updates = BTreeMap::new();
    signed_updates.insert(1, vec![1, -1, 2, 0]);
    signed_updates.insert(2, vec![0, 2, -2, 1]);
    signed_updates.insert(3, vec![-1, 1, 0, 2]);

    let generators = Generators::default();
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let round = build_honest_round("rid-tag", &selected, signed_updates, &generators, &mut rng)
        .expect("honest round");

    for client in &selected {
        let record = round.records.get(client).expect("record");
        assert!(
            submitted_tag_equation_holds(record, &selected).expect("tag equation"),
            "tag equation failed for client {client}"
        );
    }
}
