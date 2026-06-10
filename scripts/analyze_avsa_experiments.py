#!/usr/bin/env python3
"""Analyze formal AVSA experiment CSVs without fabricating results."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


RUNTIME_REQUIRED = [
    "run_id",
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "b_inf",
    "b2_sq",
    "bit_size",
    "component",
    "operation",
    "iterations",
    "warmup",
    "mean_ms",
    "p50_ms",
    "p95_ms",
    "min_ms",
    "max_ms",
    "success",
]

SIZE_REQUIRED = [
    "run_id",
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "object_type",
    "count",
    "total_bytes",
    "mean_bytes",
    "min_bytes",
    "max_bytes",
]

CORRECTNESS_REQUIRED = [
    "run_id",
    "backend",
    "case_name",
    "check_name",
    "expected",
    "observed",
    "success",
    "error",
]

RUNTIME_OUT = [
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "component",
    "operation",
    "rows",
    "iterations_total",
    "mean_ms",
    "p50_ms",
    "p95_ms",
    "median_ms",
    "std_ms",
    "min_ms",
    "max_ms",
    "success_rate",
]

COMM_OUT = [
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "object_type",
    "count",
    "total_bytes",
    "mean_bytes",
    "min_bytes",
    "max_bytes",
    "bytes_per_client",
    "bytes_per_coordinate",
    "size_category",
]

OVERHEAD_OUT = [
    "backend",
    "case_name",
    "n_selected",
    "dim",
    "base_submission_cost_ms",
    "input_validation_cost_ms",
    "client_accountability_cost_ms",
    "decision_accountability_cost_ms",
    "appeal_support_cost_ms",
    "maskcert_audit_cost_ms",
    "aggregatecert_audit_cost_ms",
    "total_avsa_audit_cost_ms",
    "incremental_accountability_overhead_ms",
    "incremental_accountability_ratio",
]

DERIVED_CLIENT_SCALING_OUT = [
    "backend",
    "case_name",
    "base_case_name",
    "dim",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "component",
    "operation",
    "mean_ms",
    "std_ms",
    "model",
    "value_source",
]

COMPARISON_OUT = [
    "scheme",
    "source",
    "value_source",
    "dataset",
    "dimension",
    "predicate",
    "operation",
    "value",
    "value_std",
    "unit",
    "scope",
    "backend",
    "n_selected",
    "case_name",
    "notes",
    "citation_key",
    "status",
]


class ExperimentError(RuntimeError):
    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Results root or one benchmark output directory.")
    parser.add_argument("--out", type=Path, default=Path("analysis"))
    parser.add_argument("--component-mapping", type=Path, default=Path("experiments/component_mapping.toml"))
    parser.add_argument("--baseline", type=Path, default=Path("experiments/baselines/rofl_acorn_provided.csv"))
    parser.add_argument("--paper-mode", action="store_true", help="Require backend=bulletproofs and correctness success.")
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs and report planned outputs without writing tables.")
    parser.add_argument(
        "--derive-client-scaling",
        action="store_true",
        help="derive client-count scaling rows from measured per-client component costs.",
    )
    parser.add_argument(
        "--derive-missing-comparison-dimensions",
        action="store_true",
        help="derive missing AVSA comparison dimensions from the largest lower measured AVSA dimension.",
    )
    parser.add_argument("--client-counts", default="8,16,32,64,128,256")
    parser.add_argument("--comparison-dimensions", default="19000,62000,273000,818000")
    parser.add_argument("--admitted-ratio", type=float, default=0.875)
    parser.add_argument("--dropout-ratio", type=float, default=0.125)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    mapping = read_mapping(args.component_mapping)
    runs = discover_runs(args.input)
    if not runs:
        raise ExperimentError(f"no AVSA CSV triplets found under {args.input}")

    runtime_rows: List[Dict[str, str]] = []
    size_rows: List[Dict[str, str]] = []
    correctness_rows: List[Dict[str, str]] = []
    warnings: List[str] = []

    for run_dir in runs:
        runtime_rows.extend(read_csv_checked(run_dir / "avsa_runtime.csv", RUNTIME_REQUIRED))
        size_rows.extend(read_csv_checked(run_dir / "avsa_sizes.csv", SIZE_REQUIRED))
        correctness_rows.extend(read_csv_checked(run_dir / "avsa_correctness.csv", CORRECTNESS_REQUIRED))

    validate_correctness(correctness_rows, args.paper_mode, warnings)
    validate_backends(runtime_rows + size_rows + correctness_rows, args.paper_mode, warnings)

    if args.dry_run:
        print(f"validated_runs={len(runs)}")
        print(f"runtime_rows={len(runtime_rows)} size_rows={len(size_rows)} correctness_rows={len(correctness_rows)}")
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    runtime_summary = summarize_runtime(runtime_rows)
    comm_summary = summarize_comm(size_rows, mapping)
    overhead_summary = summarize_overhead(runtime_summary, mapping)
    derived_client_scaling = (
        derive_client_scaling(
            runtime_summary,
            parse_count_list(args.client_counts),
            args.admitted_ratio,
            args.dropout_ratio,
        )
        if args.derive_client_scaling
        else []
    )
    avsa_comparison = build_avsa_comparison(runtime_summary, comm_summary, mapping)
    if args.derive_missing_comparison_dimensions:
        avsa_comparison.extend(
            derive_missing_comparison_dimensions(
                avsa_comparison,
                parse_count_list(args.comparison_dimensions),
            )
        )
    combined_comparison = avsa_comparison + read_baseline(args.baseline)

    write_table(args.out / "table_runtime_summary", RUNTIME_OUT, runtime_summary, "AVSA Runtime Summary")
    write_table(args.out / "table_comm_summary", COMM_OUT, comm_summary, "AVSA Communication Summary")
    write_table(args.out / "table_accountability_overhead", OVERHEAD_OUT, overhead_summary, "AVSA Accountability Overhead")
    if derived_client_scaling:
        write_table(
            args.out / "table_client_scaling_derived",
            DERIVED_CLIENT_SCALING_OUT,
            derived_client_scaling,
            "Derived AVSA Client Scaling",
        )
    write_csv(args.out / "comparison_avsa.csv", COMPARISON_OUT, avsa_comparison)
    write_csv(args.out / "comparison_merged.csv", COMPARISON_OUT, combined_comparison)
    write_table(args.out / "table_comparison_rofl_acorn", COMPARISON_OUT, combined_comparison, "AVSA, RoFL, and ACORN Comparison")

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


def discover_runs(root: Path) -> List[Path]:
    root = root.resolve()
    if (root / "avsa_runtime.csv").exists():
        return [root]
    return sorted({path.parent for path in root.rglob("avsa_runtime.csv")})


def read_csv_checked(path: Path, required: Sequence[str]) -> List[Dict[str, str]]:
    if not path.exists():
        raise ExperimentError(f"missing input CSV: {path}")
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [column for column in required if column not in fields]
        if missing:
            raise ExperimentError(f"{path} missing required columns: {', '.join(missing)}")
        return list(reader)


def validate_correctness(rows: List[Dict[str, str]], paper_mode: bool, warnings: List[str]) -> None:
    failed = [row for row in rows if not parse_bool(row.get("success"))]
    if failed and paper_mode:
        first = failed[0]
        raise ExperimentError(f"correctness failure in paper mode: {first.get('case_name')} {first.get('check_name')}")
    if failed:
        warnings.append(f"{len(failed)} correctness rows failed; affected results are not paper-ready")


def validate_backends(rows: List[Dict[str, str]], paper_mode: bool, warnings: List[str]) -> None:
    backends = sorted({row.get("backend", "") for row in rows if row.get("backend")})
    if paper_mode and any(backend != "bulletproofs" for backend in backends):
        raise ExperimentError(f"paper mode requires backend=bulletproofs, saw: {', '.join(backends)}")
    if "mock" in backends:
        warnings.append("mock backend rows are debug-only and not paper-level results")


def summarize_runtime(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    group_cols = RUNTIME_OUT[:9]
    grouped: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[key(row, group_cols)].append(row)
    out: List[Dict[str, str]] = []
    for group_key, values in sorted(grouped.items()):
        means = [to_float(row.get("mean_ms")) for row in values]
        p50s = [to_float(row.get("p50_ms")) for row in values]
        p95s = [to_float(row.get("p95_ms")) for row in values]
        iterations = [to_int(row.get("iterations")) for row in values]
        success_count = sum(1 for row in values if parse_bool(row.get("success")))
        item = dict(zip(group_cols, group_key))
        item.update(
            rows=str(len(values)),
            iterations_total=str(sum(iterations)),
            mean_ms=fmt(weighted_mean(means, iterations)),
            p50_ms=fmt(weighted_mean(p50s, iterations)),
            p95_ms=fmt(weighted_mean(p95s, iterations)),
            median_ms=fmt(median(means)),
            std_ms=fmt(stddev(means)),
            min_ms=fmt(min(to_float(row.get("min_ms")) for row in values)),
            max_ms=fmt(max(to_float(row.get("max_ms")) for row in values)),
            success_rate=fmt(success_count / len(values)),
        )
        out.append(item)
    return out


def summarize_comm(rows: List[Dict[str, str]], mapping: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, str]]:
    group_cols = COMM_OUT[:8]
    grouped: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[key(row, group_cols)].append(row)
    size_categories = invert_mapping(mapping.get("size_categories", {}))
    out: List[Dict[str, str]] = []
    for group_key, values in sorted(grouped.items()):
        count = sum(to_int(row.get("count")) for row in values)
        total_bytes = sum(to_int(row.get("total_bytes")) for row in values)
        n_selected = to_int(values[0].get("n_selected"))
        dim = to_int(values[0].get("dim"))
        object_type = values[0].get("object_type", "")
        item = dict(zip(group_cols, group_key))
        item.update(
            count=str(count),
            total_bytes=str(total_bytes),
            mean_bytes=fmt(total_bytes / count if count else 0.0),
            min_bytes=str(min(to_int(row.get("min_bytes")) for row in values)),
            max_bytes=str(max(to_int(row.get("max_bytes")) for row in values)),
            bytes_per_client=fmt(total_bytes / n_selected if n_selected else 0.0),
            bytes_per_coordinate=fmt(total_bytes / dim if dim else 0.0),
            size_category=size_categories.get(object_type, "unmapped"),
        )
        out.append(item)
    return out


def summarize_overhead(runtime_summary: List[Dict[str, str]], mapping: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, str]]:
    runtime_categories = mapping.get("runtime_categories", {})
    op_to_category = invert_mapping(runtime_categories)
    grouped: Dict[Tuple[str, str, str, str], Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for row in runtime_summary:
        group = (row["backend"], row["case_name"], row["n_selected"], row["dim"])
        operation = row["operation"]
        category = op_to_category.get(operation)
        if category:
            grouped[group][category] += to_float(row.get("mean_ms"))
    out: List[Dict[str, str]] = []
    for group, values in sorted(grouped.items()):
        validation = values.get("input_validation_cost", 0.0)
        total = values.get("total_avsa_audit_cost", 0.0)
        if total == 0.0:
            total = sum(value for name, value in values.items() if name != "total_avsa_audit_cost")
        incremental = total - validation if total >= validation else 0.0
        item = {
            "backend": group[0],
            "case_name": group[1],
            "n_selected": group[2],
            "dim": group[3],
            "base_submission_cost_ms": fmt(values.get("base_submission_cost", 0.0)),
            "input_validation_cost_ms": fmt(validation),
            "client_accountability_cost_ms": fmt(values.get("client_accountability_cost", 0.0)),
            "decision_accountability_cost_ms": fmt(values.get("decision_accountability_cost", 0.0)),
            "appeal_support_cost_ms": fmt(values.get("appeal_support_cost", 0.0)),
            "maskcert_audit_cost_ms": fmt(values.get("maskcert_audit_cost", 0.0)),
            "aggregatecert_audit_cost_ms": fmt(values.get("aggregatecert_audit_cost", 0.0)),
            "total_avsa_audit_cost_ms": fmt(total),
            "incremental_accountability_overhead_ms": fmt(incremental),
            "incremental_accountability_ratio": fmt(incremental / validation if validation else 0.0),
        }
        out.append(item)
    return out


def derive_client_scaling(
    runtime_summary: List[Dict[str, str]],
    target_counts: Sequence[int],
    admitted_ratio: float,
    dropout_ratio: float,
) -> List[Dict[str, str]]:
    base_groups: Dict[Tuple[str, str, str], List[Dict[str, str]]] = defaultdict(list)
    for row in runtime_summary:
        base_groups[(row["backend"], row["case_name"], row["dim"])].append(row)

    out: List[Dict[str, str]] = []
    for (backend, base_case_name, dim), rows in sorted(base_groups.items()):
        by_operation = {row["operation"]: row for row in rows}
        for n_selected in target_counts:
            if n_selected <= 0:
                continue
            counts = derived_counts(n_selected, admitted_ratio, dropout_ratio)
            for row in rows:
                operation = row["operation"]
                if operation == "honest_full_audit_pipeline":
                    continue
                factor, model = scaling_factor(operation, counts)
                if factor <= 0:
                    continue
                out.append(
                    derived_runtime_row(
                        row,
                        base_case_name,
                        counts,
                        factor,
                        model,
                    )
                )
            total = derived_total_verifier_cost(by_operation, counts)
            if total is not None:
                mean, std = total
                out.append(
                    {
                        "backend": backend,
                        "case_name": f"derived_n{n_selected}_d{dim}",
                        "base_case_name": base_case_name,
                        "dim": dim,
                        "n_selected": str(counts["n_selected"]),
                        "n_admitted": str(counts["n_admitted"]),
                        "n_dropped": str(counts["n_dropped"]),
                        "n_rejected": str(counts["n_rejected"]),
                        "component": "pipeline",
                        "operation": "honest_full_audit_pipeline",
                        "mean_ms": fmt(mean),
                        "std_ms": fmt(std),
                        "model": "linearized_verifier_sum",
                        "value_source": "derived_linear_model",
                    }
                )
    return out


def derived_counts(n_selected: int, admitted_ratio: float, dropout_ratio: float) -> Dict[str, int]:
    n_admitted = max(1, min(n_selected, round(n_selected * admitted_ratio)))
    n_dropped = max(0, min(n_selected - n_admitted, round(n_selected * dropout_ratio)))
    n_rejected = max(0, n_selected - n_admitted - n_dropped)
    return {
        "n_selected": n_selected,
        "n_admitted": n_admitted,
        "n_dropped": n_dropped,
        "n_rejected": n_rejected,
    }


def scaling_factor(operation: str, counts: Dict[str, int]) -> Tuple[float, str]:
    per_selected = {
        "round_generation",
        "commit_vector",
        "mask_tag_generation",
        "submit_prove",
        "submit_verify",
        "transcript_root_build",
        "receipt_verify",
    }
    per_admitted = {
        "signed_range_prove",
        "signed_range_verify",
        "l2_prove",
        "l2_verify",
        "membership_verify",
        "verify_accepted_decision",
        "verify_appeal",
    }
    if operation in per_selected:
        return float(counts["n_selected"]), "measured_per_client_times_n_selected"
    if operation in per_admitted:
        return float(counts["n_admitted"]), "measured_per_client_times_n_admitted"
    if operation == "verify_mask_certificate":
        boundary_terms = counts["n_admitted"] + counts["n_admitted"] * counts["n_dropped"]
        return float(max(1, boundary_terms)), "linearized_self_plus_boundary_mask_terms"
    if operation == "verify_aggregate_certificate":
        return float(counts["n_admitted"]), "measured_per_client_aggregate_audit_terms"
    return 1.0, "carried_constant"


def derived_runtime_row(
    row: Dict[str, str],
    base_case_name: str,
    counts: Dict[str, int],
    factor: float,
    model: str,
) -> Dict[str, str]:
    return {
        "backend": row["backend"],
        "case_name": f"derived_n{counts['n_selected']}_d{row['dim']}",
        "base_case_name": base_case_name,
        "dim": row["dim"],
        "n_selected": str(counts["n_selected"]),
        "n_admitted": str(counts["n_admitted"]),
        "n_dropped": str(counts["n_dropped"]),
        "n_rejected": str(counts["n_rejected"]),
        "component": row["component"],
        "operation": row["operation"],
        "mean_ms": fmt(to_float(row.get("mean_ms")) * factor),
        "std_ms": fmt(to_float(row.get("std_ms")) * factor),
        "model": model,
        "value_source": "derived_linear_model",
    }


def derived_total_verifier_cost(
    by_operation: Dict[str, Dict[str, str]],
    counts: Dict[str, int],
) -> Optional[Tuple[float, float]]:
    verifier_ops = [
        "submit_verify",
        "signed_range_verify",
        "l2_verify",
        "membership_verify",
        "receipt_verify",
        "verify_accepted_decision",
        "verify_mask_certificate",
        "verify_aggregate_certificate",
    ]
    total = 0.0
    variance = 0.0
    used = False
    for operation in verifier_ops:
        row = by_operation.get(operation)
        if not row:
            continue
        factor, _model = scaling_factor(operation, counts)
        total += to_float(row.get("mean_ms")) * factor
        std = to_float(row.get("std_ms")) * factor
        variance += std * std
        used = True
    return (total, math.sqrt(variance)) if used else None


def build_avsa_comparison(
    runtime_summary: List[Dict[str, str]],
    comm_summary: List[Dict[str, str]],
    mapping: Dict[str, Dict[str, List[str]]],
) -> List[Dict[str, str]]:
    runtime_by_op = {
        (row["backend"], row["case_name"], row["dim"], row["operation"]): row
        for row in runtime_summary
    }
    size_by_object = {
        (row["backend"], row["case_name"], row["dim"], row["object_type"]): row
        for row in comm_summary
    }
    groups = sorted({(row["backend"], row["case_name"], row["n_selected"], row["dim"]) for row in runtime_summary})
    out: List[Dict[str, str]] = []
    for backend, case_name, n_selected, dim in groups:
        dataset = dataset_label(case_name, dim)
        for predicate in ["q_inf", "q_2"]:
            ops = mapping.get(f"comparison_operations.{predicate}", {})
            for operation, mapped_names in ops.items():
                for mapped in mapped_names:
                    if operation == "bandwidth_per_client":
                        row = size_by_object.get((backend, case_name, dim, mapped))
                        value = to_float(row.get("mean_bytes")) / 1024.0 if row else None
                        unit = "KB"
                    else:
                        row = runtime_by_op.get((backend, case_name, dim, mapped))
                        value = to_float(row.get("mean_ms")) / 1000.0 if row else None
                        unit = "seconds"
                    if value is None:
                        continue
                    out.append(
                        comparison_row(
                            scheme="AVSA",
                            source="measured_avsa",
                            value_source="measured_avsa",
                            dataset=dataset,
                            dimension=dim,
                            predicate=predicate,
                            operation=operation,
                            value=fmt(value),
                            value_std=fmt(to_float(row.get("std_ms")) / 1000.0) if row else "",
                            unit=unit,
                            scope="per_client",
                            backend=backend,
                            n_selected=n_selected,
                            case_name=case_name,
                            notes="Derived from AVSA benchmark CSVs",
                            citation_key="",
                            status="measured",
                        )
                    )
    return out


def derive_missing_comparison_dimensions(
    rows: List[Dict[str, str]],
    target_dims: Sequence[int],
) -> List[Dict[str, str]]:
    grouped: Dict[Tuple[str, str, str, str], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("scheme") != "AVSA":
            continue
        grouped[
            (
                row.get("backend", ""),
                row.get("predicate", ""),
                row.get("operation", ""),
                row.get("unit", ""),
            )
        ].append(row)

    derived: List[Dict[str, str]] = []
    for (_backend, _predicate, _operation, _unit), group_rows in grouped.items():
        existing_dims = {to_int(row.get("dimension")) for row in group_rows}
        measured = sorted(
            [row for row in group_rows if to_float(row.get("value")) > 0],
            key=lambda row: to_int(row.get("dimension")),
        )
        for target_dim in target_dims:
            if target_dim in existing_dims:
                continue
            candidates = [
                row
                for row in measured
                if 0 < to_int(row.get("dimension")) < target_dim
                and to_int(row.get("dimension")) >= target_dim // 4
            ]
            if not candidates:
                continue
            source = candidates[-1]
            source_dim = to_int(source.get("dimension"))
            factor = target_dim / source_dim
            value = to_float(source.get("value")) * factor
            value_std = to_float(source.get("value_std")) * factor
            item = dict(source)
            item.update(
                dataset=dataset_label("", str(target_dim)),
                dimension=str(target_dim),
                value=fmt(value),
                value_std=fmt(value_std) if value_std > 0 else "",
                value_source="derived_linear_model",
                case_name=f"derived_{dataset_label('', str(target_dim)).lower()}",
                notes=(
                    f"Linear extrapolation from measured AVSA dimension {source_dim}; "
                    "not a direct benchmark"
                ),
                status="derived",
            )
            derived.append(item)
    return derived


def read_baseline(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    out = []
    for row in rows:
        value = row.get("value", "")
        status = row.get("status", "")
        value_source = "user_provided_published_baseline"
        if status.upper() == "TODO" or value == "" or value.upper() == "TODO":
            value_source = "todo_baseline"
        elif "synthetic" in row.get("source", "").lower():
            value_source = "synthetic_fixture"
        out.append(
            comparison_row(
                scheme=row.get("scheme", ""),
                source=row.get("source", ""),
                value_source=value_source,
                dataset=row.get("dataset") or row.get("model_or_dataset", ""),
                dimension=row.get("dimension", ""),
                predicate=row.get("predicate") or row.get("proof_type", ""),
                operation=row.get("operation", ""),
                value=value,
                unit=row.get("unit", ""),
                scope=row.get("scope", ""),
                backend="",
                n_selected=row.get("n_clients", ""),
                case_name="",
                notes=row.get("notes", ""),
                citation_key=row.get("citation_key", ""),
                status=status,
            )
        )
    return out


def comparison_row(**kwargs: str) -> Dict[str, str]:
    return {column: str(kwargs.get(column, "")) for column in COMPARISON_OUT}


def read_mapping(path: Path) -> Dict[str, Dict[str, List[str]]]:
    if not path.exists():
        raise ExperimentError(f"missing component mapping: {path}")
    mapping: Dict[str, Dict[str, List[str]]] = defaultdict(dict)
    section = ""
    pending_key = ""
    pending_values: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                if pending_key:
                    mapping[section][pending_key] = pending_values
                    pending_key, pending_values = "", []
                section = line.strip("[]")
                continue
            if pending_key:
                if "]" in line:
                    before = line.split("]", 1)[0]
                    pending_values.extend(parse_list_items(before))
                    mapping[section][pending_key] = pending_values
                    pending_key, pending_values = "", []
                else:
                    pending_values.extend(parse_list_items(line))
                continue
            if "=" in line:
                name, value = [part.strip() for part in line.split("=", 1)]
                if value.startswith("[") and not value.endswith("]"):
                    pending_key = name
                    pending_values = parse_list_items(value[1:])
                else:
                    mapping[section][name] = parse_list_items(value.strip("[]"))
    if pending_key:
        mapping[section][pending_key] = pending_values
    return dict(mapping)


def parse_list_items(text: str) -> List[str]:
    return [part.strip().strip('"').strip("'") for part in text.split(",") if part.strip().strip(",")]


def invert_mapping(mapping: Dict[str, List[str]]) -> Dict[str, str]:
    out = {}
    for category, names in mapping.items():
        for name in names:
            out[name] = category
    return out


def write_table(stem: Path, columns: Sequence[str], rows: List[Dict[str, str]], title: str) -> None:
    write_csv(stem.with_suffix(".csv"), columns, rows)
    write_markdown(stem.with_suffix(".md"), columns, rows, title)
    write_latex(stem.with_suffix(".tex"), columns, rows, title)


def write_csv(path: Path, columns: Sequence[str], rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, columns: Sequence[str], rows: List[Dict[str, str]], title: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"# {title}\n\n")
        handle.write("| " + " | ".join(columns) + " |\n")
        handle.write("| " + " | ".join(["---"] * len(columns)) + " |\n")
        for row in rows:
            handle.write("| " + " | ".join(str(row.get(column, "")).replace("|", "\\|") for column in columns) + " |\n")


def write_latex(path: Path, columns: Sequence[str], rows: List[Dict[str, str]], title: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("% Generated from measured AVSA CSVs and provided baseline data.\n")
        handle.write("\\begin{table}[t]\n\\centering\n\\small\n")
        handle.write(f"\\caption{{{latex(title)}}}\n")
        handle.write("\\begin{tabular}{" + "l" * len(columns) + "}\n\\toprule\n")
        handle.write(" & ".join(latex(column) for column in columns) + " \\\\\n\\midrule\n")
        for row in rows:
            handle.write(" & ".join(latex(row.get(column, "")) for column in columns) + " \\\\\n")
        handle.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")


def key(row: Dict[str, str], columns: Sequence[str]) -> Tuple[str, ...]:
    return tuple(row.get(column, "") for column in columns)


def parse_bool(value: Optional[str]) -> bool:
    return str(value).lower() in {"true", "1", "yes"}


def parse_count_list(value: str) -> List[int]:
    counts = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        counts.append(int(part))
    return counts


def to_float(value: Optional[str]) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


def to_int(value: Optional[str]) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def weighted_mean(values: Sequence[float], weights: Sequence[int]) -> float:
    total = sum(max(weight, 0) for weight in weights)
    return sum(value * max(weight, 0) for value, weight in zip(values, weights)) / total if total else 0.0


def median(values: Sequence[float]) -> float:
    return statistics.median(values) if values else 0.0


def stddev(values: Sequence[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def fmt(value: float) -> str:
    if not math.isfinite(value):
        return ""
    return f"{value:.6g}"


def dataset_label(case_name: str, dim: str) -> str:
    by_dim = {"19000": "MNIST", "62000": "CIFAR10-S", "273000": "CIFAR10-L", "818000": "Shakespeare"}
    return by_dim.get(str(dim), case_name)


def latex(value: object) -> str:
    text = str(value)
    repl = {"\\": "\\textbackslash{}", "&": "\\&", "%": "\\%", "$": "\\$", "#": "\\#", "_": "\\_", "{": "\\{", "}": "\\}"}
    return "".join(repl.get(ch, ch) for ch in text)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExperimentError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
