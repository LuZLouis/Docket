# AVSA Benchmark Analysis

These scripts consume Round 8 benchmark CSV files and generate paper-ready
tables, optional plots, and a reproducibility manifest. They do not run FL
training, add protocol logic, or invent experimental values.

## Inputs

Provide a directory containing:

- `avsa_runtime.csv`
- `avsa_sizes.csv`
- `avsa_correctness.csv`

For example, after a real Bulletproofs smoke benchmark:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset smoke --backend bulletproofs --iters 2 --warmup 1 --out target/avsa_bench_smoke_bp
```

## Analysis

Run:

```powershell
python scripts/analyze_avsa_results.py --input target/avsa_bench_smoke_bp --out target/avsa_analysis_smoke_bp
```

The script writes:

- `target/avsa_analysis/runtime_summary.csv`
- `target/avsa_analysis/runtime_summary.md`
- `target/avsa_analysis/runtime_summary.tex`
- `target/avsa_analysis/size_summary.csv`
- `target/avsa_analysis/size_summary.md`
- `target/avsa_analysis/size_summary.tex`
- `target/avsa_analysis/correctness_summary.csv`
- `target/avsa_analysis/correctness_summary.md`
- `target/avsa_analysis/analysis_manifest.json`

Strict mode is enabled by default. Missing required schema columns or failed
correctness rows stop the analysis. Use `--no-strict` only when intentionally
auditing partial or failed runs; failed cases are still recorded and are not
silently dropped.

Mock backend rows require `--allow-mock`. Mock timings are useful for pipeline
checks only and must not be reported as real cryptographic proof performance.

## Plots

Run:

```powershell
python scripts/plot_avsa_results.py --input target/avsa_analysis_smoke_bp --out target/avsa_analysis_smoke_bp
```

If `matplotlib` is available, the script writes PNG and PDF plots:

- `runtime_by_dimension`
- `component_breakdown`
- `proof_and_certificate_sizes`
- `audit_pipeline_breakdown`

Plots with insufficient measured data are skipped with warnings. The script
does not fabricate missing dimensions or backend results.

## Self-Test

Run:

```powershell
python scripts/analyze_avsa_results.py --self-test
```

The self-test creates temporary sample CSV files, validates schemas, generates
summaries, and checks that the manifest is produced.

## LaTeX Tables

The generated `.tex` files are standalone `table` snippets using `booktabs`
commands. Include `\usepackage{booktabs}` in the paper preamble before pasting
them into a manuscript.

Only paste tables generated from correctness-passing real-backend benchmark
runs for performance claims. Mock-backend tables may be used only to document
software pipeline checks.
