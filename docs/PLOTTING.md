# AVSA Evaluation Plotting

The formal evaluation plotting script reads CSVs under `results/` and writes
paper-facing figures and LaTeX tables. It does not run benchmarks and does not
invent missing data.

## Command

```powershell
python experiments/scripts/plot_evaluation.py --results results --figures figures --tables tables --png-preview
```

## Figures

- `figures/common_path_overhead.pdf` and `.svg`
- `figures/tag_vs_opening_size.pdf` and `.svg`
- `figures/tag_vs_opening_time.pdf` and `.svg`

With `--png-preview`, PNG previews are also written.

## Tables

- `tables/appeal_cost.tex`
- `tables/malicious_server_detection.tex`
- `tables/baseline_overhead_percent.tex`

The script uses `matplotlib` when available. If the dependency is missing, it
still writes tables and skips figures with a warning.
