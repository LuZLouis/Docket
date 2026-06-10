# AVSA Benchmarking

Round 8 adds a small benchmark runner for the reference implementation. It
measures implemented protocol layers on deterministic simulated signed update
vectors and writes CSV files for runtime, object sizes, and correctness checks.
It does not implement new cryptographic protocols or FL training.

## Commands

```powershell
cargo test
cargo run --release --bin bench_avsa -- --preset smoke --backend mock --iters 5 --warmup 1 --out target/avsa_bench
cargo run --release --bin bench_avsa -- --preset mnist_like --backend mock --n-selected 16 --iters 10 --out target/avsa_bench
cargo run --release --features bulletproofs --bin bench_avsa -- --preset smoke --backend bulletproofs --iters 2 --warmup 1 --out target/avsa_bench_smoke_bp
cargo run --release --features bulletproofs --bin bench_avsa -- --preset small --backend bulletproofs --iters 3 --out target/avsa_bench_real
```

The mock backend is test-only and not cryptographically secure. Do not present
mock-backend timings as real proof-system performance.

## Presets

- `smoke`: `n_selected=4`, `dim=8`
- `small`: `n_selected=8`, `dim=64`
- `medium`: `n_selected=16`, `dim=1024`
- `mnist_like`: `dim=19000`
- `cifar10_s_like`: `dim=62000`
- `cifar10_l_like`: `dim=273000`
- `shakespeare_like`: `dim=818000`

The FL-like presets are available only when explicitly selected on the CLI.
They are intentionally not used by the cargo test smoke checks.

## Backends

- `mock`: enabled by default through `MockRangeProofBackend`.
- `bulletproofs`: available with `--features bulletproofs` or `--features bulletproofs-backend`.

Every CSV row includes the backend name.

## CSV Outputs

The runner writes three files under `--out`.

`avsa_runtime.csv`

```text
run_id,backend,case_name,n_selected,n_admitted,n_dropped,n_rejected,dim,b_inf,b2_sq,bit_size,component,operation,iterations,warmup,mean_ms,p50_ms,p95_ms,min_ms,max_ms,success
```

`avsa_sizes.csv`

```text
run_id,backend,case_name,n_selected,n_admitted,n_dropped,n_rejected,dim,object_type,count,total_bytes,mean_bytes,min_bytes,max_bytes
```

`avsa_correctness.csv`

```text
run_id,backend,case_name,check_name,expected,observed,success,error
```

## Measured Operations

The runner measures implemented operations only:

- `round_generation`
- `commit_vector`
- `mask_tag_generation`
- `submit_prove`
- `submit_verify`
- `signed_range_prove`
- `signed_range_verify`
- `l2_prove`
- `l2_verify`
- `transcript_root_build`
- `membership_verify`
- `receipt_verify`
- `verify_accepted_decision`
- `verify_appeal`
- `verify_mask_certificate`
- `verify_aggregate_certificate`
- `honest_full_audit_pipeline`

Runtime statistics use warmup iterations followed by measured iterations and
report mean, p50, p95, min, and max milliseconds.

## Size Measurements

Object sizes use existing canonical serialization where available. For objects
without protocol-level canonical bytes, the benchmark module uses a narrow
benchmark-only byte encoding with canonical scalar and Ristretto point
serialization. It does not use `Debug` string lengths.

Current size rows include:

- `ClientRecord`
- `SubmitProof`
- `SignedRangeProof`
- `L2Proof`
- `RecordDigest`
- `TranscriptRoot`
- `Transcript`
- `MembershipProof`
- `Receipt`
- `DecisionCertificate`
- `AppealInput`
- `MaskCertificate`
- `AggregateCertificate`
- `AggregateOutput`

## Correctness Checks

The benchmark writes correctness rows for the honest simulated pipeline:

- SubmitProof verification succeeds for all records.
- Signed range verification succeeds for all records.
- L2 verification succeeds for all records.
- Accepted decision verification succeeds for admitted clients.
- Mask certificate verification succeeds.
- Aggregate certificate verification succeeds.
- The full honest audit pipeline succeeds.

If a check fails, `bench_avsa` exits nonzero unless `--allow-failures` is set.
