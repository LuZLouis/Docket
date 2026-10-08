# Docket Rust Reference Implementation

This repository contains the Rust reference implementation and evaluation
artifacts for the manuscript:

**Docket: Server Accountability for Input-Validated Secure Aggregation**

The manuscript is currently submitted to **IEEE Transactions on Information
Forensics and Security (TIFS)**. Docket adds public accountability to secure
aggregation with input validation. The implementation covers the protocol
algebra, admission and recovery logic, public audit, aggregate verification,
and the benchmark and analysis tooling used in the paper.

The evaluation uses synthetic signed update vectors encoded in the scalar
field. This isolates the cryptographic and protocol costs measured in the
paper.

## Repository Layout

```text
src/              Rust library and bench_docket binary
tests/            Rust integration tests
experiments/      Benchmark configurations, fixtures, and baseline CSV inputs
results/          Benchmark CSV outputs
analysis/         Derived paper-facing CSV/Markdown/LaTeX tables
figures/          Generated plots from the analysis outputs
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
- `matplotlib` for plot generation. The analysis scripts use the Python
  standard library for CSV processing.

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
cargo run --bin bench_docket -- --help
```

## Running Docket Benchmarks

The complete Docket evaluation suite can be run from the repository root:

```powershell
cargo run --release --bin bench_docket -- --full --time-mode calibrated --repetitions 5 --out results
```

For Bulletproofs-backed component runs:

```powershell
cargo run --release --features bulletproofs --bin bench_docket -- --preset small --backend bulletproofs --iters 10 --warmup 2 --out results/docket_internal_small
```

The RoFL/ACORN-aligned configurations used by the analysis scripts are listed
in `experiments/configs/rofl_acorn_aligned.toml`. To print the corresponding
run commands:

```powershell
python scripts/print_experiment_commands.py --config experiments/configs/rofl_acorn_aligned.toml
```

The baseline CSV files contain the available published or author-provided
RoFL and ACORN measurements used in the paper.

## Analysis and Figures

To regenerate paper-facing tables from benchmark outputs:

```powershell
python scripts/analyze_docket_experiments.py --input results --out analysis --paper-mode --derive-client-scaling --baseline experiments/baselines/rofl_acorn_provided.csv
python scripts/merge_baselines.py --docket analysis --baseline experiments/baselines/rofl_acorn_provided.csv --out analysis/comparison_merged.csv
```

To regenerate plots when `matplotlib` is installed:

```powershell
python scripts/plot_docket_experiments.py --input analysis --out figures --png-preview
```

The synthetic fixtures under `experiments/fixtures/` support reproducible
protocol and benchmark execution.
