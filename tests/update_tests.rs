use avsa_rs::sim::dataset::sample_signed_update;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn sampled_updates_within_bound() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let b_inf = 3;
    for _ in 0..64 {
        let update = sample_signed_update(16, b_inf, &mut rng).expect("sample update");
        assert_eq!(update.len(), 16);
        assert!(update.iter().all(|value| (-b_inf..=b_inf).contains(value)));
    }
}
