#!/usr/bin/env python3
"""Analyze AVSA Round 8 benchmark CSV outputs.

The script validates schemas, gates measurements on correctness rows, writes
CSV/Markdown/LaTeX summaries, and records a reproducibility manifest. It uses
only measured CSV data and never fabricates missing benchmark values.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


RUNTIME_FILE = "avsa_runtime.csv"
SIZE_FILE = "avsa_sizes.csv"
CORRECTNESS_FILE = "avsa_correctness.csv"

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

RUNTIME_GROUP = [
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "component",
    "operation",
]

SIZE_GROUP = [
    "backend",
    "case_name",
    "n_selected",
    "n_admitted",
    "n_dropped",
    "n_rejected",
    "dim",
    "object_type",
]

CORRECTNESS_GROUP = ["backend", "case_name", "check_name"]

RUNTIME_SUMMARY_COLUMNS = RUNTIME_GROUP + [
    "rows",
    "iterations_total",
    "mean_ms",
    "p50_ms",
    "p95_ms",
    "min_ms",
    "max_ms",
    "std_ms",
    "success_rate",
]

SIZE_SUMMARY_COLUMNS = SIZE_GROUP + [
    "count",
    "total_bytes",
    "mean_bytes",
    "min_bytes",
    "max_bytes",
    "bytes_per_client",
    "bytes_per_dimension",
]

CORRECTNESS_SUMMARY_COLUMNS = CORRECTNESS_GROUP + [
    "rows",
    "passed",
    "failed",
    "success_rate",
    "first_error",
]

TABLE_FILES = [
    "runtime_summary.csv",
    "runtime_summary.md",
    "runtime_summary.tex",
    "size_summary.csv",
    "size_summary.md",
    "size_summary.tex",
    "correctness_summary.csv",
    "correctness_summary.md",
]


class AnalysisError(RuntimeError):
    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Directory containing Round 8 CSV files.")
    parser.add_argument("--out", type=Path, default=Path("target/avsa_analysis"))
    strict_group = parser.add_mutually_exclusive_group()
    strict_group.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        default=True,
        help="Fail on schema or correctness failures. This is the default.",
    )
    strict_group.add_argument(
        "--no-strict",
        dest="strict",
        action="store_false",
        help="Warn and continue on schema or correctness failures.",
    )
    parser.add_argument(
        "--allow-mock",
        action="store_true",
        help="Allow mock-backend rows to be summarized. Mock rows are labeled, not real crypto.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a temporary fixture test and exit.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        return self_test()
    if args.input is None:
        raise AnalysisError("--input is required unless --self-test is used")
    warnings = analyze(args.input, args.out, args.strict, args.allow_mock)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 0


def analyze(input_dir: Path, out_dir: Path, strict: bool, allow_mock: bool) -> List[str]:
    input_dir = input_dir.resolve()
    out_dir = out_dir.resolve()
    warnings: List[str] = []
    out_dir.mkdir(parents=True, exist_ok=True)

    runtime_rows = read_required_csv(
        input_dir / RUNTIME_FILE, RUNTIME_REQUIRED, strict, warnings
    )
    size_rows = read_required_csv(input_dir / SIZE_FILE, SIZE_REQUIRED, strict, warnings)
    correctness_rows = read_required_csv(
        input_dir / CORRECTNESS_FILE, CORRECTNESS_REQUIRED, strict, warnings
    )

    backends = sorted(
        {
            row.get("backend", "")
            for row in runtime_rows + size_rows + correctness_rows
            if row.get("backend", "")
        }
    )
    cases = sorted(
        {
            row.get("case_name", "")
            for row in runtime_rows + size_rows + correctness_rows
            if row.get("case_name", "")
        }
    )

    if "mock" in backends and not allow_mock:
        message = (
            "mock backend rows are present; rerun with --allow-mock to summarize "
            "test-only mock results"
        )
        if strict:
            raise AnalysisError(message)
        warnings.append(message)
    if "mock" in backends:
        warnings.append(
            "mock backend rows are test-only and are not cryptographic performance data"
        )

    correctness_summary = summarize_correctness(correctness_rows)
    write_table_set(
        out_dir,
        "correctness_summary",
        CORRECTNESS_SUMMARY_COLUMNS,
        correctness_summary,
        "AVSA Correctness Summary",
        write_latex=False,
    )

    failed = [row for row in correctness_summary if int(row["failed"]) > 0]
    if failed:
        message = f"{len(failed)} correctness group(s) contain failures"
        if strict:
            write_manifest(
                input_dir,
                out_dir,
                [RUNTIME_FILE, SIZE_FILE, CORRECTNESS_FILE],
                backends,
                cases,
                warnings + [message],
            )
            raise AnalysisError(message)
        warnings.append(message)

    failed_cases = {
        (row["backend"], row["case_name"])
        for row in correctness_summary
        if int(row["failed"]) > 0
    }
    runtime_summary = summarize_runtime(runtime_rows, failed_cases, strict, warnings)
    size_summary = summarize_sizes(size_rows, failed_cases, strict, warnings)

    write_table_set(
        out_dir,
        "runtime_summary",
        RUNTIME_SUMMARY_COLUMNS,
        runtime_summary,
        "AVSA Runtime Summary",
        write_latex=True,
    )
    write_table_set(
        out_dir,
        "size_summary",
        SIZE_SUMMARY_COLUMNS,
        size_summary,
        "AVSA Size Summary",
        write_latex=True,
    )

    write_manifest(
        input_dir,
        out_dir,
        [RUNTIME_FILE, SIZE_FILE, CORRECTNESS_FILE],
        backends,
        cases,
        warnings,
    )
    return warnings


def read_required_csv(
    path: Path, required: Sequence[str], strict: bool, warnings: List[str]
) -> List[Dict[str, str]]:
    if not path.exists():
        raise AnalysisError(f"required input CSV is missing: {path}")
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        missing = [column for column in required if column not in fieldnames]
        if missing:
            message = f"{path.name} missing required columns: {', '.join(missing)}"
            if strict:
                raise AnalysisError(message)
            warnings.append(message)
        return list(reader)


def summarize_runtime(
    rows: List[Dict[str, str]],
    failed_cases: Set[Tuple[str, str]],
    strict: bool,
    warnings: List[str],
) -> List[Dict[str, str]]:
    grouped: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[group_key(row, RUNTIME_GROUP)].append(row)

    out = []
    for key in sorted(grouped):
        values = grouped[key]
        iterations_total = sum(to_int(row.get("iterations"), 0) for row in values)
        means = [to_float(row.get("mean_ms"), 0.0) for row in values]
        weighted_mean = weighted_average(
            means, [to_int(row.get("iterations"), 1) for row in values]
        )
        p50_values = [to_float(row.get("p50_ms"), 0.0) for row in values]
        p95_values = [to_float(row.get("p95_ms"), 0.0) for row in values]
        success_count = sum(1 for row in values if parse_bool(row.get("success")))
        summary = dict(zip(RUNTIME_GROUP, key))
        summary.update(
            {
                "rows": str(len(values)),
                "iterations_total": str(iterations_total),
                "mean_ms": f"{weighted_mean:.6f}",
                "p50_ms": f"{percentile(p50_values, 0.50):.6f}",
                "p95_ms": f"{percentile(p95_values, 0.95):.6f}",
                "min_ms": f"{min(to_float(row.get('min_ms'), 0.0) for row in values):.6f}",
                "max_ms": f"{max(to_float(row.get('max_ms'), 0.0) for row in values):.6f}",
                "std_ms": f"{stddev(means):.6f}",
                "success_rate": f"{success_count / len(values):.6f}",
            }
        )
        mark_failed_case(summary, failed_cases, strict, warnings, "runtime")
        out.append(summary)
    return out


def summarize_sizes(
    rows: List[Dict[str, str]],
    failed_cases: Set[Tuple[str, str]],
    strict: bool,
    warnings: List[str],
) -> List[Dict[str, str]]:
    grouped: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[group_key(row, SIZE_GROUP)].append(row)

    out = []
    for key in sorted(grouped):
        values = grouped[key]
        total_count = sum(to_int(row.get("count"), 0) for row in values)
        total_bytes = sum(to_int(row.get("total_bytes"), 0) for row in values)
        n_selected = to_int(values[0].get("n_selected"), 0)
        dim = to_int(values[0].get("dim"), 0)
        summary = dict(zip(SIZE_GROUP, key))
        summary.update(
            {
                "count": str(total_count),
                "total_bytes": str(total_bytes),
                "mean_bytes": f"{safe_div(total_bytes, total_count):.6f}",
                "min_bytes": str(min(to_int(row.get("min_bytes"), 0) for row in values)),
                "max_bytes": str(max(to_int(row.get("max_bytes"), 0) for row in values)),
                "bytes_per_client": f"{safe_div(total_bytes, n_selected):.6f}",
                "bytes_per_dimension": f"{safe_div(total_bytes, dim):.6f}",
            }
        )
        mark_failed_case(summary, failed_cases, strict, warnings, "size")
        out.append(summary)
    return out


def summarize_correctness(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    grouped: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[group_key(row, CORRECTNESS_GROUP)].append(row)

    out = []
    for key in sorted(grouped):
        values = grouped[key]
        passed = sum(1 for row in values if parse_bool(row.get("success")))
        failed = len(values) - passed
        first_error = ""
        for row in values:
            if not parse_bool(row.get("success")):
                first_error = row.get("error") or row.get("observed") or "failure"
                break
        summary = dict(zip(CORRECTNESS_GROUP, key))
        summary.update(
            {
                "rows": str(len(values)),
                "passed": str(passed),
                "failed": str(failed),
                "success_rate": f"{passed / len(values):.6f}",
                "first_error": first_error,
            }
        )
        out.append(summary)
    return out


def mark_failed_case(
    row: Dict[str, str],
    failed_cases: Set[Tuple[str, str]],
    strict: bool,
    warnings: List[str],
    table_name: str,
) -> None:
    case = (row.get("backend", ""), row.get("case_name", ""))
    if case in failed_cases and not strict:
        row["success_rate"] = "0.000000"
        warnings.append(
            f"{table_name} summary row for backend={case[0]} case={case[1]} marked failed"
        )


def write_table_set(
    out_dir: Path,
    stem: str,
    columns: Sequence[str],
    rows: List[Dict[str, str]],
    title: str,
    write_latex: bool,
) -> None:
    write_csv(out_dir / f"{stem}.csv", columns, rows)
    write_markdown(out_dir / f"{stem}.md", columns, rows, title)
    if write_latex:
        write_latex_table(out_dir / f"{stem}.tex", columns, rows, title)


def write_csv(path: Path, columns: Sequence[str], rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_markdown(
    path: Path, columns: Sequence[str], rows: List[Dict[str, str]], title: str
) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"# {title}\n\n")
        if not rows:
            handle.write("No rows.\n")
            return
        handle.write("| " + " | ".join(columns) + " |\n")
        handle.write("| " + " | ".join(["---"] * len(columns)) + " |\n")
        for row in rows:
            handle.write(
                "| "
                + " | ".join(markdown_cell(row.get(column, "")) for column in columns)
                + " |\n"
            )


def write_latex_table(
    path: Path, columns: Sequence[str], rows: List[Dict[str, str]], title: str
) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("% Generated from AVSA benchmark CSVs. Do not edit by hand.\n")
        handle.write("\\begin{table}[t]\n\\centering\n")
        handle.write("\\small\n")
        handle.write(f"\\caption{{{latex_escape(title)}}}\n")
        handle.write("\\begin{tabular}{" + "l" * len(columns) + "}\n")
        handle.write("\\toprule\n")
        handle.write(" & ".join(latex_escape(column) for column in columns) + " \\\\\n")
        handle.write("\\midrule\n")
        for row in rows:
            handle.write(
                " & ".join(latex_escape(row.get(column, "")) for column in columns)
                + " \\\\\n"
            )
        handle.write("\\bottomrule\n")
        handle.write("\\end{tabular}\n")
        handle.write("\\end{table}\n")


def write_manifest(
    input_dir: Path,
    out_dir: Path,
    input_files: Sequence[str],
    backends: Sequence[str],
    cases: Sequence[str],
    warnings: Sequence[str],
) -> None:
    manifest_path = out_dir / "analysis_manifest.json"
    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "input_directory": str(input_dir),
        "output_directory": str(out_dir),
        "input_files": list(input_files),
        "input_file_hashes": {
            name: sha256_file(input_dir / name) if (input_dir / name).exists() else "missing"
            for name in input_files
        },
        "analysis_command": " ".join(sys.argv),
        "python_version": platform.python_version(),
        "rust_version": command_output(["rustc", "--version"]),
        "git_commit": command_output(["git", "rev-parse", "HEAD"]),
        "git_dirty": git_dirty_status(),
        "backend_values_seen": list(backends),
        "case_values_seen": list(cases),
        "plots_generated": existing_manifest_list(manifest_path, "plots_generated"),
        "tables_generated": list(TABLE_FILES),
        "warnings": sorted(set(warnings)),
    }
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def existing_manifest_list(path: Path, key: str) -> List[str]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle).get(key, [])
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def group_key(row: Dict[str, str], columns: Sequence[str]) -> Tuple[str, ...]:
    return tuple(row.get(column, "") for column in columns)


def parse_bool(value: Optional[str]) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def to_int(value: Optional[str], default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def to_float(value: Optional[str], default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default


def weighted_average(values: Sequence[float], weights: Sequence[int]) -> float:
    total_weight = sum(max(weight, 0) for weight in weights)
    if total_weight == 0:
        return 0.0
    return sum(value * max(weight, 0) for value, weight in zip(values, weights)) / total_weight


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(math.ceil((len(ordered) - 1) * q))
    return ordered[min(index, len(ordered) - 1)]


def stddev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def markdown_cell(value: str) -> str:
    return str(value).replace("|", "\\|")


def latex_escape(value: str) -> str:
    text = str(value)
    replacements = {
        "\\": "\\textbackslash{}",
        "&": "\\&",
        "%": "\\%",
        "$": "\\$",
        "#": "\\#",
        "_": "\\_",
        "{": "\\{",
        "}": "\\}",
        "~": "\\textasciitilde{}",
        "^": "\\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=Path.cwd(),
        )
    except OSError:
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def git_dirty_status() -> str:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=Path.cwd(),
        )
    except OSError:
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return "true" if completed.stdout.strip() else "false"


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="avsa_analysis_selftest_") as temp:
        root = Path(temp)
        fixture = root / "fixture"
        output = root / "analysis"
        fixture.mkdir()
        write_self_test_fixture(fixture)
        warnings = analyze(fixture, output, strict=True, allow_mock=True)
        expected = [
            output / "runtime_summary.csv",
            output / "runtime_summary.md",
            output / "runtime_summary.tex",
            output / "size_summary.csv",
            output / "size_summary.md",
            output / "size_summary.tex",
            output / "correctness_summary.csv",
            output / "correctness_summary.md",
            output / "analysis_manifest.json",
        ]
        missing = [str(path) for path in expected if not path.exists()]
        if missing:
            raise AnalysisError(f"self-test missing outputs: {missing}")
        with (output / "analysis_manifest.json").open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        for key in [
            "timestamp_utc",
            "input_directory",
            "output_directory",
            "input_file_hashes",
            "backend_values_seen",
            "case_values_seen",
            "tables_generated",
            "warnings",
        ]:
            if key not in manifest:
                raise AnalysisError(f"self-test manifest missing key {key}")
        print("self-test passed")
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def write_self_test_fixture(path: Path) -> None:
    runtime_rows = [
        {
            "run_id": "selftest-mock-smoke",
            "backend": "mock",
            "case_name": "smoke",
            "n_selected": "4",
            "n_admitted": "3",
            "n_dropped": "1",
            "n_rejected": "0",
            "dim": "8",
            "b_inf": "3",
            "b2_sq": "72",
            "bit_size": "8",
            "component": "submit",
            "operation": "submit_verify",
            "iterations": "2",
            "warmup": "1",
            "mean_ms": "1.25",
            "p50_ms": "1.20",
            "p95_ms": "1.30",
            "min_ms": "1.10",
            "max_ms": "1.40",
            "success": "true",
        },
        {
            "run_id": "selftest-mock-smoke",
            "backend": "mock",
            "case_name": "smoke",
            "n_selected": "4",
            "n_admitted": "3",
            "n_dropped": "1",
            "n_rejected": "0",
            "dim": "8",
            "b_inf": "3",
            "b2_sq": "72",
            "bit_size": "8",
            "component": "pipeline",
            "operation": "honest_full_audit_pipeline",
            "iterations": "2",
            "warmup": "1",
            "mean_ms": "4.50",
            "p50_ms": "4.40",
            "p95_ms": "4.70",
            "min_ms": "4.20",
            "max_ms": "4.80",
            "success": "true",
        },
    ]
    size_rows = [
        {
            "run_id": "selftest-mock-smoke",
            "backend": "mock",
            "case_name": "smoke",
            "n_selected": "4",
            "n_admitted": "3",
            "n_dropped": "1",
            "n_rejected": "0",
            "dim": "8",
            "object_type": "ClientRecord",
            "count": "4",
            "total_bytes": "4000",
            "mean_bytes": "1000",
            "min_bytes": "1000",
            "max_bytes": "1000",
        },
        {
            "run_id": "selftest-mock-smoke",
            "backend": "mock",
            "case_name": "smoke",
            "n_selected": "4",
            "n_admitted": "3",
            "n_dropped": "1",
            "n_rejected": "0",
            "dim": "8",
            "object_type": "SubmitProof",
            "count": "4",
            "total_bytes": "800",
            "mean_bytes": "200",
            "min_bytes": "200",
            "max_bytes": "200",
        },
    ]
    correctness_rows = [
        {
            "run_id": "selftest-mock-smoke",
            "backend": "mock",
            "case_name": "smoke",
            "check_name": "submit_verify_all",
            "expected": "success",
            "observed": "all submit proofs verified",
            "success": "true",
            "error": "",
        }
    ]
    write_csv(path / RUNTIME_FILE, RUNTIME_REQUIRED, runtime_rows)
    write_csv(path / SIZE_FILE, SIZE_REQUIRED, size_rows)
    write_csv(path / CORRECTNESS_FILE, CORRECTNESS_REQUIRED, correctness_rows)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AnalysisError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
