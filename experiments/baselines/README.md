# SAIV Published Baseline Data

`saiv_published_baselines.csv` is the baseline input used by the formal AVSA
evaluation suite. It contains only user-provided or published SAIV values. The
analysis scripts do not synthesize missing rows.

```text
scheme,source,dataset,dimension,predicate,operation,value,unit,scope,notes
```

Current coverage:

- `RoFL`: present, copied from the user-provided baseline table.
- `ACORN`: present, copied from the user-provided baseline table.

Metric meanings in the normalized CSV:

- `C`: single-client client computation time, encoded as `client_prove_time_per_client`, in seconds.
- `S`: server verification time for one client, encoded as `server_verify_time_per_client`, in seconds.
- `B`: per-client bandwidth, encoded as `bandwidth_per_client`, in KB.
- `q_inf`: infinity-norm or signed range-style predicate.
- `q_2`: L2-norm predicate.

Dataset dimensions:

- `MNIST`: `19000`
- `CIFAR10-S`: `62000`
- `CIFAR10-L`: `273000`
- `Shakespeare`: `818000`

The normalized file contains 48 provided RoFL/ACORN rows: 4 datasets x 2
predicates x 3 operations x 2 schemes. These values should not be edited unless
a more authoritative source is added and the source label is updated.

`rofl_acorn_provided.csv` keeps the earlier Round 10 long-format table with
`citation_key` and `status` columns. `saiv_published_baselines.csv` is the
schema used by `experiments/scripts/analyze_baseline_overhead.py`.

`rofl_acorn_published_template.csv` is a blank/TODO template for replacing or
extending baseline rows from paper text, artifact logs, or local reproduction.
Rows with missing numeric values must keep `status=TODO`; analysis and merge
scripts preserve them as `todo_baseline` rather than inventing numbers.

Do not compare AVSA full-audit cost directly against RoFL/ACORN without stating
scope. The formal evaluation uses common-path AVSA audit overhead as the default
incremental cost and reports dispute/opening-path overhead separately.

RoFL and ACORN must not be rerun by this suite.
