# Bulletproofs Range Backend

AVSA has a real Bulletproofs-backed implementation of the Round 5
`RangeProofBackend` trait behind a Cargo feature.

## Features

Either feature name works:

```powershell
cargo test --features bulletproofs-backend
cargo test --features bulletproofs
```

The shorter `bulletproofs` feature is an alias for `bulletproofs-backend`.

## Dependencies

The backend uses:

- `bulletproofs = "5.0.0"`
- `curve25519-dalek = "4"`
- `merlin = "3"`

## Statement

The signed predicate is:

```text
x_j in [-B, B]
y_j = x_j + B in [0, 2B]
C_j^+ = C_j * g^B = g^{x_j+B} h^{rho_j}
```

The prover computes the shifted values and shifted commitments through the
shared `signed_range_prove` wrapper. The verifier recomputes `C_j^+` from the
public AVSA commitments and rejects if the stored shifted commitments differ.

## Generator Mapping

The Bulletproofs backend constructs the Bulletproofs `PedersenGens` directly
from AVSA's generator pair:

```text
PedersenGens.B = AVSA g
PedersenGens.B_blinding = AVSA h
```

This means the Bulletproofs proof is verified against the same Pedersen
commitments used by the AVSA commitment layer.

## Commitment Checks

During proving, the backend asks the Bulletproofs library to create commitments
and compares them against AVSA's expected shifted commitments before returning a
proof. During verification, it passes the verifier's recomputed shifted
commitments directly to Bulletproofs.

The proof object stores only serialized Bulletproofs proof bytes. It does not
store signed values, shifted values, blindings, or witness vectors.

## Range Construction

The backend proves both shifted values and their complements:

```text
y_j = x_j + B
2B - y_j = B - x_j
```

This enforces the exact signed interval while still using ordinary unsigned
Bulletproofs range proofs.

## Bit Sizes and Dimensions

Supported Bulletproofs bit sizes are:

```text
8, 16, 32, 64
```

The aggregation size passed to the Bulletproofs library must be a power of two.
The implementation chunks non-power-of-two dimensions into deterministic
Bulletproofs subproofs. Each subproof pads only its local aggregation size to a
power of two and binds the chunk index and range into the Merlin transcript.
The provided benchmark presets use dimensions that satisfy this restriction.

## Commands

Run real-backend tests:

```powershell
cargo test --features bulletproofs
```

Run real-backend benchmarks:

```powershell
cargo run --release --features bulletproofs --bin bench_avsa -- --preset smoke --backend bulletproofs --iters 2 --warmup 1 --out target/avsa_bench_smoke_bp
cargo run --release --features bulletproofs --bin bench_avsa -- --preset small --backend bulletproofs --iters 2 --warmup 1 --out target/avsa_bench_small_bp
```

Analyze a real-backend run:

```powershell
python scripts/analyze_avsa_results.py --input target/avsa_bench_smoke_bp --out target/avsa_analysis_smoke_bp
python scripts/plot_avsa_results.py --input target/avsa_analysis_smoke_bp --out target/avsa_analysis_smoke_bp
```

Do not pass `--allow-mock` for real-backend-only result directories.

## Known Limitations

- The backend is feature-gated to keep default smoke tests quick.
- Unsupported aggregation dimensions are rejected rather than padded.
- Benchmarks still use simulated signed vectors, not FL training or datasets.
