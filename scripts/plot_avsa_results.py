#!/usr/bin/env python3
"""Plot AVSA analysis summaries when matplotlib is available."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


RUNTIME_SUMMARY = "runtime_summary.csv"
SIZE_SUMMARY = "size_summary.csv"
MANIFEST = "analysis_manifest.json"


class PlotError(RuntimeError):
    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Analysis output directory.")
    parser.add_argument("--out", type=Path, default=Path("target/avsa_analysis"))
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    warnings: List[str] = []
    generated: List[str] = []
    input_dir = args.input.resolve()
    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    runtime_rows = read_csv(input_dir / RUNTIME_SUMMARY, warnings)
    size_rows = read_csv(input_dir / SIZE_SUMMARY, warnings)

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as error:  # pragma: no cover - environment dependent
        warnings.append(f"matplotlib unavailable; plots skipped: {error}")
        update_manifest(out_dir, generated, warnings)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        return 0

    plot_runtime_by_dimension(runtime_rows, out_dir, generated, warnings, plt)
    plot_component_breakdown(runtime_rows, out_dir, generated, warnings, plt)
    plot_proof_and_certificate_sizes(size_rows, out_dir, generated, warnings, plt)
    plot_audit_pipeline_breakdown(runtime_rows, out_dir, generated, warnings, plt)

    update_manifest(out_dir, generated, warnings)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"generated {len(generated)} plot file(s)")
    return 0


def read_csv(path: Path, warnings: List[str]) -> List[Dict[str, str]]:
    if not path.exists():
        warnings.append(f"summary CSV missing, skipping dependent plots: {path}")
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def plot_runtime_by_dimension(
    rows: List[Dict[str, str]], out_dir: Path, generated: List[str], warnings: List[str], plt
) -> None:
    pipeline_rows = [row for row in rows if row.get("operation") == "honest_full_audit_pipeline"]
    if not pipeline_rows:
        warnings.append("runtime_by_dimension skipped: honest_full_audit_pipeline rows missing")
        return
    dims = {to_int(row.get("dim")) for row in pipeline_rows}
    if len(dims) < 2:
        warnings.append("runtime_by_dimension skipped: fewer than two dimensions")
        return

    grouped: Dict[str, List[Tuple[int, float]]] = defaultdict(list)
    for row in pipeline_rows:
        label = f"{row.get('backend', '')}/{row.get('case_name', '')}"
        grouped[label].append((to_int(row.get("dim")), to_float(row.get("mean_ms"))))

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for label, values in sorted(grouped.items()):
        values.sort()
        ax.plot([dim for dim, _ in values], [ms for _, ms in values], marker="o", label=label)
    ax.set_xlabel("dimension")
    ax.set_ylabel("mean runtime (ms)")
    ax.set_title("Honest full audit pipeline by dimension")
    ax.legend()
    ax.grid(True, alpha=0.25)
    save_plot(fig, out_dir, "runtime_by_dimension", generated, plt)


def plot_component_breakdown(
    rows: List[Dict[str, str]], out_dir: Path, generated: List[str], warnings: List[str], plt
) -> None:
    if not rows:
        warnings.append("component_breakdown skipped: runtime summary empty")
        return
    grouped: Dict[str, float] = defaultdict(float)
    for row in rows:
        label = f"{row.get('backend', '')}/{row.get('case_name', '')}/{row.get('component', '')}"
        grouped[label] += to_float(row.get("mean_ms"))
    if not grouped:
        warnings.append("component_breakdown skipped: no runtime values")
        return
    labels, values = unzip_items(sorted(grouped.items(), key=lambda item: item[0]))
    fig, ax = plt.subplots(figsize=(max(7, len(labels) * 0.35), 4.8))
    ax.bar(range(len(labels)), values)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel("sum of mean runtime (ms)")
    ax.set_title("Runtime component breakdown")
    ax.grid(True, axis="y", alpha=0.25)
    fig.tight_layout()
    save_plot(fig, out_dir, "component_breakdown", generated, plt)


def plot_proof_and_certificate_sizes(
    rows: List[Dict[str, str]], out_dir: Path, generated: List[str], warnings: List[str], plt
) -> None:
    interesting = {
        "SubmitProof",
        "SignedRangeProof",
        "L2Proof",
        "MaskCertificate",
        "AggregateCertificate",
        "DecisionCertificate",
        "MembershipProof",
        "Receipt",
    }
    selected = [row for row in rows if row.get("object_type") in interesting]
    if not selected:
        warnings.append("proof_and_certificate_sizes skipped: no proof/certificate rows")
        return
    grouped: Dict[str, float] = defaultdict(float)
    for row in selected:
        label = f"{row.get('backend', '')}/{row.get('object_type', '')}"
        grouped[label] += to_float(row.get("mean_bytes"))
    labels, values = unzip_items(sorted(grouped.items(), key=lambda item: item[0]))
    fig, ax = plt.subplots(figsize=(max(7, len(labels) * 0.45), 4.8))
    ax.bar(range(len(labels)), values)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel("mean bytes")
    ax.set_title("Proof and certificate sizes")
    ax.grid(True, axis="y", alpha=0.25)
    fig.tight_layout()
    save_plot(fig, out_dir, "proof_and_certificate_sizes", generated, plt)


def plot_audit_pipeline_breakdown(
    rows: List[Dict[str, str]], out_dir: Path, generated: List[str], warnings: List[str], plt
) -> None:
    operations = {
        "submit_verify",
        "signed_range_verify",
        "l2_verify",
        "membership_verify",
        "receipt_verify",
        "verify_accepted_decision",
        "verify_appeal",
        "verify_mask_certificate",
        "verify_aggregate_certificate",
        "honest_full_audit_pipeline",
    }
    selected = [row for row in rows if row.get("operation") in operations]
    if not selected:
        warnings.append("audit_pipeline_breakdown skipped: no audit operation rows")
        return
    grouped: Dict[str, float] = defaultdict(float)
    for row in selected:
        label = f"{row.get('backend', '')}/{row.get('operation', '')}"
        grouped[label] += to_float(row.get("mean_ms"))
    labels, values = unzip_items(sorted(grouped.items(), key=lambda item: item[0]))
    fig, ax = plt.subplots(figsize=(max(7, len(labels) * 0.45), 4.8))
    ax.bar(range(len(labels)), values)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=55, ha="right")
    ax.set_ylabel("mean runtime (ms)")
    ax.set_title("Audit pipeline breakdown")
    ax.grid(True, axis="y", alpha=0.25)
    fig.tight_layout()
    save_plot(fig, out_dir, "audit_pipeline_breakdown", generated, plt)


def save_plot(fig, out_dir: Path, stem: str, generated: List[str], plt) -> None:
    for suffix in ["png", "pdf"]:
        path = out_dir / f"{stem}.{suffix}"
        fig.savefig(path, bbox_inches="tight")
        generated.append(path.name)
    plt.close(fig)


def update_manifest(out_dir: Path, generated: List[str], warnings: List[str]) -> None:
    manifest_path = out_dir / MANIFEST
    manifest: Dict[str, object] = {}
    if manifest_path.exists():
        try:
            with manifest_path.open("r", encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, json.JSONDecodeError):
            manifest = {}
    manifest.setdefault("timestamp_utc", datetime.now(timezone.utc).isoformat())
    manifest.setdefault("output_directory", str(out_dir))
    manifest["plots_generated"] = sorted(set(generated))
    old_warnings = manifest.get("warnings", [])
    if not isinstance(old_warnings, list):
        old_warnings = []
    manifest["warnings"] = sorted(set([str(value) for value in old_warnings] + warnings))
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def unzip_items(items: Sequence[Tuple[str, float]]) -> Tuple[List[str], List[float]]:
    return [key for key, _ in items], [value for _, value in items]


def to_int(value: Optional[str]) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def to_float(value: Optional[str]) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PlotError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
