# AVSA Formal Evaluation Suite

This directory contains the formal evaluation suite for the revised AVSA
semantics: AVSA is measured as a public audit layer for a SAIV system under a
malicious aggregation server. These experiments do not run FL training and do
not rerun RoFL or ACORN.

## Experiments

1. Common-path audit overhead:
`experiments/configs/common_path.toml` writes `results/common_path.csv`.
   It measures transcript/root checks, accepted-decision verification,
   `MaskCert^tag` generation and verification, `Cert_agg` generation, and
   `VerifyAggregate`.

2. Tag certificate versus opening certificate:
   `experiments/configs/tag_vs_opening.toml` writes
   `results/tag_vs_opening.csv`. It compares compact common-path
   `MaskCert^tag` against dispute-path `MaskCert^open` as boundary size varies.

3. Appeal and rejection audit:
   `experiments/configs/appeal_cost.toml` writes `results/appeal_cost.csv`.
   It measures valid rejection, false rejection, and omitted-record appeals.

4. Malicious-server detection:
   `experiments/configs/malicious_server_detection.toml` writes
   `results/malicious_server_detection.csv`. It injects false acceptance, false
   rejection, omission, equivocation, unsupported recovery, missing opening,
   extra opening, wrong opening, wrong tag mask, and wrong aggregate.

5. Published SAIV baseline overhead:
`bench_avsa --full` writes `results/baseline_overhead_percent.csv` directly.
The standalone script `experiments/scripts/analyze_baseline_overhead.py` can
regenerate that file from existing CSVs.

## CSV Schemas

`results/common_path.csv`

```text
experiment,run_id,n,dimension,admitted,excluded,dropped,tag_mode,scope,phase,operation,time_ms,extra_bytes,full_public_bytes,result_label
```

`results/tag_vs_opening.csv`

```text
experiment,run_id,n,dimension,admitted,non_admitted,boundary_size,tag_mode,certificate_mode,generation_ms,verification_ms,certificate_header_bytes,raw_opening_bytes,total_extra_bytes,result_label
```

`results/appeal_cost.csv`

```text
experiment,run_id,n,dimension,appeal_case,root_mode,requires_record_body,verify_ms,evidence_bytes,expected_label,actual_label,passed
```

`results/malicious_server_detection.csv`

```text
experiment,run_id,n,dimension,attack,verifier,expected_label,actual_label,detected,passed,detection_scope,time_ms
```

`results/baseline_overhead_percent.csv`

```text
scheme,dataset,dimension,predicate,baseline_client_time_s,avsa_client_extra_s,client_extra_percent,baseline_server_time_s,avsa_server_extra_s,server_extra_percent,baseline_bandwidth_kb,avsa_common_extra_kb,common_bandwidth_extra_percent,avsa_opening_extra_kb,opening_bandwidth_extra_percent,baseline_source,comparison_note
```

## Stable Verifier Labels

The suite uses stable labels intended for paper tables:

```text
accept
valid
serverFault(falseReject)
serverFault(omission)
reject(validation)
reject(record)
reject(maskTag)
reject(domain)
reject(selfOpening)
reject(pairOpening)
reject(maskSum)
reject(aggregateSum)
equivocation(root)
equivocation(admittedSet)
equivocation(aggregate)
```

## User-Run Command

Full formal AVSA run over `n in {10,20,50,100,200}`, dimensions
`{19000,62000,273000,818000}`, and 5 repetitions:

```powershell
cargo run --release --bin bench_avsa -- --full --time-mode calibrated --repetitions 5
```

Equivalent explicit output-directory form:

```powershell
cargo run --release --bin bench_avsa -- --full --time-mode calibrated --repetitions 5 --out results
```

Do not use mock proof-component smoke results as paper-level cryptographic
performance data.

## Baseline Handling

`experiments/baselines/saiv_published_baselines.csv` contains only available
RoFL/ACORN published or user-provided values. The baseline analysis script
reports overhead for available RoFL/ACORN rows only and does not invent missing
baseline numbers.
