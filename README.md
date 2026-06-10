# AVSA Rust Reference Implementation

This repository contains the Rust reference implementation and evaluation
artifacts for the manuscript:

**AVSA: Accountable and Verifiable Secure Aggregation**

The manuscript is currently submitted to **IEEE Transactions on Dependable and
Secure Computing (TDSC)**. AVSA is a public-accountability layer for secure
aggregation with input validation. The implementation focuses on protocol
algebra, public audit judgments, mask accountability, aggregate verification,
and benchmark/analysis tooling used by the paper.

The repository does not contain a federated-learning training stack or real
datasets. Update vectors are simulated signed values encoded into the scalar
field so that the audit and certificate logic can be tested reproducibly.

## Repository Layout

```text
src/              Rust library and bench_avsa binary
tests/            Rust integration tests
experiments/      Benchmark configurations, fixtures, and baseline CSV inputs
results/          Existing benchmark CSV outputs
analysis/         Derived paper-facing CSV/Markdown/LaTeX tables
figures/          Generated plots from the included analysis outputs
tables/           Generated LaTeX table fragments
scripts/          Python analysis, merge, and plotting utilities
docs/             Additional implementation notes
```

## Environment

Required:

- Rust stable toolchain with Cargo, using the Rust 2021 edition.
- Git, for cloning and version tracking.

Optional, for analysis and plotting:

- Python 3.9 or newer.
- `matplotlib`, only if plot generation is required. The analysis scripts use
  the Python standard library for CSV processing.

Optional, for Bulletproofs-based predicate benchmarks:

- Build with `--features bulletproofs` or `--features bulletproofs-backend`.

No external cryptographic system library is required by the Rust crate.

## Build and Test

```powershell
cargo build
cargo test
```

To compile and test the optional Bulletproofs backend:

```powershell
cargo test --features bulletproofs
```

The benchmark binary exposes its command-line options with:

```powershell
cargo run --bin bench_avsa -- --help
```

## Running AVSA Benchmarks

The formal AVSA evaluation suite can be run from the repository root:

```powershell
cargo run --release --bin bench_avsa -- --full --time-mode calibrated --repetitions 5 --out results
```

For Bulletproofs-backed component runs:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset small --backend bulletproofs --iters 10 --warmup 2 --out results/avsa_internal_small
```

The RoFL/ACORN-aligned configurations used by the analysis scripts are listed
in `experiments/configs/rofl_acorn_aligned.toml`. To print the concrete run
commands:

```powershell
python scripts/print_experiment_commands.py --config experiments/configs/rofl_acorn_aligned.toml
```

The included baseline CSV files contain only available published or
author-provided baseline values. The scripts do not synthesize missing RoFL or
ACORN measurements.

## Analysis and Figures

To regenerate paper-facing tables from existing benchmark outputs:

```powershell
python scripts/analyze_avsa_experiments.py --input results --out analysis --paper-mode --derive-client-scaling --baseline experiments/baselines/rofl_acorn_provided.csv
python scripts/merge_baselines.py --avsa analysis --baseline experiments/baselines/rofl_acorn_provided.csv --out analysis/comparison_merged.csv
```

To regenerate plots when `matplotlib` is installed:

```powershell
python scripts/plot_avsa_experiments.py --input analysis --out figures --png-preview
```

The synthetic fixture directory under `experiments/fixtures/` is for script
development only and should not be treated as paper-level cryptographic
performance data.

## Implementation Scope

The current code includes:

- public AVSA parameter checks and signed fixed-point simulation helpers;
- vector arithmetic over `curve25519_dalek::Scalar`;
- Ristretto/Pedersen commitment helpers;
- complete selected-client pairwise mask graph logic;
- self masks, pairwise masks, submitted masks, masked updates, and mask tags;
- submission binding for masked updates, commitments, mask tags, and witnesses;
- deterministic transcript roots, receipt checks, decision certificates, and
  appeal outcomes;
- raw mask certificates with exact opening-domain checks;
- aggregate certificates binding admitted decisions, masks, and released sums;
- signed range and L2 predicate interfaces, with mock and optional Bulletproofs
  backends;
- benchmark and analysis tooling for AVSA-specific accountability overhead.

The implementation is a research prototype for reproducibility and protocol
checking. It is not a production deployment of federated learning, secure
network transport, ledger publication, or client orchestration.
