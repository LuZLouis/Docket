# AVSA Formal Evaluation

The current evaluation treats AVSA as a public audit layer for a SAIV system
with a malicious aggregation server. It does not benchmark FL training and does
not rerun RoFL or ACORN.

The source-of-truth instructions are in `experiments/README.md`.

## Outputs

- `results/common_path.csv`
- `results/tag_vs_opening.csv`
- `results/appeal_cost.csv`
- `results/malicious_server_detection.csv`
- `results/baseline_overhead_percent.csv`

## Full Commands

```powershell
cargo run --release --bin bench_avsa -- --full --time-mode calibrated --repetitions 5
```

This writes exactly:

- `results/common_path.csv`
- `results/tag_vs_opening.csv`
- `results/appeal_cost.csv`
- `results/malicious_server_detection.csv`
- `results/baseline_overhead_percent.csv`

The command covers `n in {10,20,50,100,200}`,
`dimension in {19000,62000,273000,818000}`, and 5 repetitions.
