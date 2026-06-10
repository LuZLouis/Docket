# AVSA Experiment Scripts

This directory contains Round 10 analysis helpers for turning AVSA benchmark
CSV outputs into paper-facing tables, comparison CSVs, and figures.

## 1. Run AVSA Benchmarks Locally

Use Bulletproofs backend rows for paper-level results:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset small --backend bulletproofs --iters 10 --warmup 2 --out results/avsa_internal_small
```

Client-count scaling is derived, not run as full multi-client Bulletproofs
rounds. Generate derived rows after analysis with `--derive-client-scaling`.
The old full-run pattern below is only useful for debugging small dimensions:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset medium --backend bulletproofs --n-selected 8 --n-admitted 7 --n-dropped 1 --n-rejected 0 --dim 1024 --iters 10 --warmup 2 --out results/scale_clients_n8
cargo run --release --features bulletproofs --bin bench_avsa -- --preset medium --backend bulletproofs --n-selected 16 --n-admitted 14 --n-dropped 2 --n-rejected 0 --dim 1024 --iters 10 --warmup 2 --out results/scale_clients_n16
```

Dimension-scaling examples:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset smoke --backend bulletproofs --n-selected 16 --n-admitted 14 --n-dropped 2 --n-rejected 0 --dim 8 --iters 5 --warmup 1 --out results/scale_dimension_smoke
cargo run --release --features bulletproofs --bin bench_avsa -- --preset medium --backend bulletproofs --n-selected 16 --n-admitted 14 --n-dropped 2 --n-rejected 0 --dim 1024 --iters 5 --warmup 1 --out results/scale_dimension_1024
```

The exact RoFL/ACORN-aligned dimensions and the 50-client setup are listed in
`experiments/configs/rofl_acorn_aligned.toml`. Print the concrete commands:

```powershell
python scripts/print_experiment_commands.py --config experiments/configs/rofl_acorn_aligned.toml
```

The Bulletproofs backend chunks non-power-of-two dimensions internally, but
the 273k and 818k cases are intentionally heavy.

## 2. Analyze Results

```powershell
python scripts/analyze_avsa_experiments.py --input results --out analysis --paper-mode --derive-client-scaling --baseline experiments/baselines/rofl_acorn_provided.csv
```

`--paper-mode` rejects AVSA rows whose backend is not `bulletproofs` and fails
on correctness failures.

## 3. Merge Baselines

```powershell
python scripts/merge_baselines.py --avsa analysis --baseline experiments/baselines/rofl_acorn_provided.csv --out analysis/comparison_merged.csv
```

The merged comparison preserves `value_source`, so tables can separate
`measured_avsa`, `published_baseline`, `todo_baseline`, and
`synthetic_fixture` rows.

## 4. Plot Figures

```powershell
python scripts/plot_avsa_experiments.py --input analysis --out figures
```

Add `--png-preview` to emit PNG files in addition to PDF and SVG:

```powershell
python scripts/plot_avsa_experiments.py --input analysis --out figures --png-preview
```

Expected paper-facing figures:

- `fig_avsa_overhead_by_dimension`: 2x3 AVSA internal overhead grid.
- `fig_avsa_overhead_by_clients`: 2x3 AVSA client-scaling overhead grid.
- `fig_comparison_rofl_acorn`: 2x3 RoFL/ACORN/AVSA comparison grid.

The comparison grid only includes AVSA rows at the aligned dimensions
`19k`, `62k`, `273k`, and `818k`. If those AVSA runs have not been generated
yet, the figure will show the provided RoFL/ACORN baselines and warn that AVSA
aligned rows are missing.

## 5. Dry-Run With Synthetic Fixtures

The fixture directory is for script development only:

```powershell
python scripts/analyze_avsa_experiments.py --input experiments/fixtures/synthetic_smoke --out analysis_synthetic --paper-mode --dry-run
python scripts/merge_baselines.py --avsa analysis_synthetic --baseline experiments/baselines/rofl_acorn_published_template.csv --out analysis_synthetic/comparison_merged.csv --dry-run
python scripts/plot_avsa_experiments.py --input analysis_synthetic --out figures_synthetic --dry-run
```

Synthetic fixture rows are not experimental results.

## 6. Output Tables

The analysis script writes:

- `analysis/table_runtime_summary.csv`
- `analysis/table_runtime_summary.md`
- `analysis/table_runtime_summary.tex`
- `analysis/table_comm_summary.csv`
- `analysis/table_comm_summary.md`
- `analysis/table_comm_summary.tex`
- `analysis/table_accountability_overhead.csv`
- `analysis/table_accountability_overhead.md`
- `analysis/table_accountability_overhead.tex`
- `analysis/table_comparison_rofl_acorn.csv`
- `analysis/table_comparison_rofl_acorn.md`
- `analysis/table_comparison_rofl_acorn.tex`

Copy Markdown tables for quick review and LaTeX tables for manuscript drafts
after confirming correctness rows and backend labels.
