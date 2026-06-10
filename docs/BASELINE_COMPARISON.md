# SAIV Baseline Comparison

AVSA baseline comparison uses published or user-provided SAIV values only.
RoFL and ACORN are not rerun by this repository.

## Baseline Input

The normalized baseline CSV is:

```text
experiments/baselines/saiv_published_baselines.csv
```

Schema:

```text
scheme,source,dataset,dimension,predicate,operation,value,unit,scope,notes
```

Current rows cover RoFL and ACORN.

## Overhead Output

The full benchmark command writes the overhead CSV directly:

```powershell
cargo run --release --bin bench_avsa -- --full
```

After `results/common_path.csv` and `results/tag_vs_opening.csv` already exist,
the standalone script can regenerate only the baseline-overhead file:

```powershell
python experiments/scripts/analyze_baseline_overhead.py --baseline experiments/baselines/saiv_published_baselines.csv --common results/common_path.csv --opening results/tag_vs_opening.csv --out results/baseline_overhead_percent.csv
```

Output schema:

```text
scheme,dataset,dimension,predicate,baseline_client_time_s,avsa_client_extra_s,client_extra_percent,baseline_server_time_s,avsa_server_extra_s,server_extra_percent,baseline_bandwidth_kb,avsa_common_extra_kb,common_bandwidth_extra_percent,avsa_opening_extra_kb,opening_bandwidth_extra_percent,baseline_source,comparison_note
```

`avsa_common_extra_kb` is the default AVSA incremental overhead.
`avsa_opening_extra_kb` is the dispute-path opening-certificate overhead and
must be reported separately.
