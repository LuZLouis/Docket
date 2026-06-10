#!/usr/bin/env python3
"""Compute AVSA overhead over published RoFL/ACORN baselines.

The script ignores LZKSA rows if they appear in the input file. It does not
rerun baseline systems and does not fabricate missing values.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


COMMON_HEADER = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "admitted",
    "excluded",
    "dropped",
    "tag_mode",
    "scope",
    "phase",
    "operation",
    "time_ms",
    "time_source",
    "cost_model",
    "space_cost_model",
    "extra_bytes",
    "full_public_bytes",
    "result_label",
]

TAG_HEADER = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "admitted",
    "non_admitted",
    "boundary_size",
    "tag_mode",
    "certificate_mode",
    "generation_ms",
    "generation_time_source",
    "generation_cost_model",
    "verification_ms",
    "verification_time_source",
    "verification_cost_model",
    "certificate_header_bytes",
    "aggregate_mask_bytes",
    "raw_opening_bytes",
    "total_extra_bytes",
    "result_label",
]

BASELINE_HEADER = [
    "scheme",
    "source",
    "dataset",
    "dimension",
    "predicate",
    "operation",
    "value",
    "unit",
    "scope",
    "notes",
]

OUTPUT_HEADER = [
    "scheme",
    "dataset",
    "dimension",
    "predicate",
    "baseline_client_time_s",
    "avsa_client_extra_s",
    "client_extra_percent",
    "baseline_server_time_s",
    "avsa_server_extra_s",
    "server_extra_percent",
    "baseline_bandwidth_kb",
    "avsa_common_extra_kb",
    "common_bandwidth_extra_percent",
    "avsa_opening_extra_kb",
    "opening_bandwidth_extra_percent",
    "baseline_source",
    "comparison_note",
]

COMPARISON_NOTE = "published baseline, not same-hardware controlled comparison"


def read_rows(path: Path, header: list[str]) -> list[dict]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != header:
            raise SystemExit(f"{path} header mismatch:\nexpected={header}\nactual={reader.fieldnames}")
        return list(reader)


def f(row: dict, key: str) -> float:
    return float(row[key])


def i(row: dict, key: str) -> int:
    return int(row[key])


def percent(extra: float, baseline: float) -> float:
    return 100.0 * extra / baseline if baseline > 0 else 0.0


def common_overheads(rows: list[dict]) -> dict[int, dict[str, float]]:
    by_dim = defaultdict(list)
    for row in rows:
        by_dim[i(row, "dimension")].append(row)
    out = {}
    for dim, dim_rows in by_dim.items():
        preferred_n = min({i(row, "n") for row in dim_rows}, key=lambda n: abs(n - 50))
        selected = [row for row in dim_rows if i(row, "n") == preferred_n]
        admitted = max(1, i(selected[0], "admitted"))
        reps = max(1, sum(1 for row in selected if row["phase"] == "client_submit") // 2)
        client_ms = sum(f(row, "time_ms") for row in selected if row["phase"] == "client_submit") / reps
        server_ms = sum(f(row, "time_ms") for row in selected if row["phase"] == "auditor_verify") / reps
        extra_bytes = sum(int(row["extra_bytes"]) for row in selected) / reps
        out[dim] = {
            "client_s": client_ms / 1000.0 / admitted,
            "server_s": server_ms / 1000.0 / admitted,
            "common_kb": extra_bytes / 1024.0 / admitted,
        }
    return out


def opening_overheads(rows: list[dict]) -> dict[int, float]:
    out = {}
    for row in rows:
        if row["certificate_mode"] != "open" or i(row, "n") != 50:
            continue
        admitted = max(1, i(row, "admitted"))
        dim = i(row, "dimension")
        out.setdefault(dim, []).append(int(row["total_extra_bytes"]) / 1024.0 / admitted)
    return {dim: sum(values) / len(values) for dim, values in out.items()}


def baseline_groups(rows: list[dict]) -> dict[tuple, dict]:
    groups = {}
    for row in rows:
        if row["scheme"].lower() == "lzksa":
            continue
        key = (row["scheme"], row["dataset"], int(row["dimension"]), row["predicate"])
        entry = groups.setdefault(
            key,
            {
                "scheme": row["scheme"],
                "dataset": row["dataset"],
                "dimension": int(row["dimension"]),
                "predicate": row["predicate"],
                "source": row["source"],
            },
        )
        operation = row["operation"]
        if operation == "client_prove_time_per_client":
            entry["client_s"] = float(row["value"])
        elif operation == "server_verify_time_per_client":
            entry["server_s"] = float(row["value"])
        elif operation == "bandwidth_per_client":
            entry["bandwidth_kb"] = float(row["value"])
    return groups


def build_output(args: argparse.Namespace) -> list[dict]:
    baselines = baseline_groups(read_rows(args.baseline, BASELINE_HEADER))
    common = common_overheads(read_rows(args.common, COMMON_HEADER))
    opening = opening_overheads(read_rows(args.opening, TAG_HEADER)) if args.opening.exists() else {}
    output = []
    for group in baselines.values():
        if not {"client_s", "server_s", "bandwidth_kb"} <= group.keys():
            continue
        dim = group["dimension"]
        if dim not in common:
            continue
        c = common[dim]
        o = opening.get(dim, 0.0)
        output.append(
            {
                "scheme": group["scheme"],
                "dataset": group["dataset"],
                "dimension": dim,
                "predicate": group["predicate"],
                "baseline_client_time_s": f"{group['client_s']:.6g}",
                "avsa_client_extra_s": f"{c['client_s']:.6g}",
                "client_extra_percent": f"{percent(c['client_s'], group['client_s']):.6g}",
                "baseline_server_time_s": f"{group['server_s']:.6g}",
                "avsa_server_extra_s": f"{c['server_s']:.6g}",
                "server_extra_percent": f"{percent(c['server_s'], group['server_s']):.6g}",
                "baseline_bandwidth_kb": f"{group['bandwidth_kb']:.6g}",
                "avsa_common_extra_kb": f"{c['common_kb']:.6g}",
                "common_bandwidth_extra_percent": f"{percent(c['common_kb'], group['bandwidth_kb']):.6g}",
                "avsa_opening_extra_kb": f"{o:.6g}",
                "opening_bandwidth_extra_percent": f"{percent(o, group['bandwidth_kb']):.6g}",
                "baseline_source": group["source"],
                "comparison_note": COMPARISON_NOTE,
            }
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=Path("experiments/baselines/saiv_published_baselines.csv"))
    parser.add_argument("--common", type=Path, default=Path("results/common_path.csv"))
    parser.add_argument("--opening", type=Path, default=Path("results/tag_vs_opening.csv"))
    parser.add_argument("--out", type=Path, default=Path("results/baseline_overhead_percent.csv"))
    args = parser.parse_args()

    rows = build_output(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_HEADER)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} baseline-overhead rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
