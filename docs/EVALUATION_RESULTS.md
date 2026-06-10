# Evaluation Results Workflow

This document explains how to regenerate AVSA benchmark CSVs and convert them
into tables, plots, and a reproducibility manifest.

## Round 8 Benchmark CLI

Run a tiny mock smoke benchmark:

```powershell
cargo run --release --bin bench_avsa -- --preset smoke --backend mock --iters 2 --warmup 1 --out target/avsa_bench_smoke
```

Run a larger mock pipeline check:

```powershell
cargo run --release --bin bench_avsa -- --preset small --backend mock --iters 5 --warmup 1 --out target/avsa_bench_small
```

Run a real backend benchmark only when the feature is available:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset smoke --backend bulletproofs --iters 2 --warmup 1 --out target/avsa_bench_smoke_bp
cargo run --release --features bulletproofs --bin bench_avsa -- --preset small --backend bulletproofs --iters 3 --warmup 1 --out target/avsa_bench_real
```

The benchmark directory must contain:

- `avsa_runtime.csv`
- `avsa_sizes.csv`
- `avsa_correctness.csv`

## Round 9 Analysis

Generate summaries:

```powershell
python scripts/analyze_avsa_results.py --input target/avsa_bench_smoke --out target/avsa_analysis --allow-mock
```

For real Bulletproofs results, omit `--allow-mock`:

```powershell
python scripts/analyze_avsa_results.py --input target/avsa_bench_smoke_bp --out target/avsa_analysis_smoke_bp
```

Generate plots:

```powershell
python scripts/plot_avsa_results.py --input target/avsa_analysis --out target/avsa_analysis
```

Outputs are written under `target/avsa_analysis` by default.

## Generated Artifacts

Tables:

- `runtime_summary.csv`
- `runtime_summary.md`
- `runtime_summary.tex`
- `size_summary.csv`
- `size_summary.md`
- `size_summary.tex`
- `correctness_summary.csv`
- `correctness_summary.md`

Plots, when enough measured data and `matplotlib` are available:

- `runtime_by_dimension.png`
- `runtime_by_dimension.pdf`
- `component_breakdown.png`
- `component_breakdown.pdf`
- `proof_and_certificate_sizes.png`
- `proof_and_certificate_sizes.pdf`
- `audit_pipeline_breakdown.png`
- `audit_pipeline_breakdown.pdf`

Manifest:

- `analysis_manifest.json`

The manifest records input file hashes, tool versions when available, git
metadata when available, observed backend and case values, generated tables,
generated plots, and warnings.

## Correctness Gating

Analysis always reads `avsa_correctness.csv` before presenting measurements.
If any correctness row has `success=false`, the failure is recorded in
`correctness_summary.csv` and `correctness_summary.md`.

Strict mode is enabled by default and fails on correctness failures. With
`--no-strict`, analysis continues but affected cases are marked as failed. Failed
rows are never silently dropped.

## Mock Backend Interpretation

The mock backend is test-only and not cryptographically secure. Mock-backend
results are acceptable for checking CSV generation, table generation, plotting,
and end-to-end software wiring. They are not safe to use as cryptographic
performance numbers in the paper.

Use real Bulletproofs backend CSVs for proof-cost claims, and keep the backend
column visible in tables and plots.

## Paper-Safe Outputs

Safe to paste into the paper after the underlying benchmark run passes
correctness:

- `runtime_summary.tex`
- `size_summary.tex`
- PDF plots generated from real-backend CSVs
- selected rows from `correctness_summary.md` as an audit statement

Do not paste mock-backend performance tables as if they were real cryptographic
measurements.
