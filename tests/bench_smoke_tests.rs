use avsa_rs::bench::cases::{BenchBackend, BenchConfig, BenchPreset};
use avsa_rs::bench::runner::{
    generate_bench_round, run, CORRECTNESS_HEADER, RUNTIME_HEADER, SIZE_HEADER,
};
use avsa_rs::proof::range::MockRangeProofBackend;
use avsa_rs::transcript::record_digest;
use std::fs;
use std::path::PathBuf;

fn smoke_config(name: &str) -> BenchConfig {
    let mut config = BenchConfig::for_preset(BenchPreset::Smoke);
    config.backend = BenchBackend::Mock;
    config.iters = 1;
    config.warmup = 0;
    config.seed = 777;
    config.out_dir = temp_out_dir(name);
    config
}

fn temp_out_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "avsa_bench_{name}_{}_{}",
        std::process::id(),
        777_u64
    ))
}

#[test]
fn smoke_preset_generation_succeeds() {
    let config = smoke_config("generation");
    let round =
        generate_bench_round::<MockRangeProofBackend>(&config).expect("smoke benchmark round");

    assert_eq!(round.round.selected.len(), 4);
    assert_eq!(round.round.records.len(), 4);
    assert_eq!(round.records[0].dim(), 8);
    assert_eq!(round.signed_range_proofs.len(), 4);
    assert_eq!(round.l2_proofs.len(), 4);
}

#[test]
fn runner_writes_csv_files_with_expected_headers_and_rows() {
    let config = smoke_config("csv");
    let _ = fs::remove_dir_all(&config.out_dir);

    let summary = run(&config).expect("benchmark runner");
    assert!(summary.success);
    assert!(summary.runtime_rows > 0);
    assert!(summary.size_rows > 0);
    assert!(summary.correctness_rows > 0);

    let runtime =
        fs::read_to_string(config.out_dir.join("avsa_runtime.csv")).expect("runtime CSV contents");
    let sizes =
        fs::read_to_string(config.out_dir.join("avsa_sizes.csv")).expect("size CSV contents");
    let correctness = fs::read_to_string(config.out_dir.join("avsa_correctness.csv"))
        .expect("correctness CSV contents");

    assert_eq!(runtime.lines().next(), Some(RUNTIME_HEADER));
    assert_eq!(sizes.lines().next(), Some(SIZE_HEADER));
    assert_eq!(correctness.lines().next(), Some(CORRECTNESS_HEADER));
    assert!(runtime.lines().count() > 1);
    assert!(sizes.lines().count() > 1);
    assert!(correctness.lines().count() > 1);
    assert!(runtime.lines().skip(1).any(|line| line.contains(",mock,")));
    assert!(sizes.lines().skip(1).any(|line| line.contains(",mock,")));
    assert!(correctness
        .lines()
        .skip(1)
        .all(|line| line.split(',').nth(6) == Some("true")));
}

#[test]
fn repeated_seed_yields_stable_public_generated_objects() {
    let config = smoke_config("stable_seed");
    let first = generate_bench_round::<MockRangeProofBackend>(&config).expect("first round");
    let second = generate_bench_round::<MockRangeProofBackend>(&config).expect("second round");

    assert_eq!(first.transcript.root, second.transcript.root);
    let first_record = first.records.first().expect("first record");
    let second_record = second.records.first().expect("second record");
    assert_eq!(record_digest(first_record), record_digest(second_record));
    assert_eq!(first.aggregate_certificate, second.aggregate_certificate);
}
