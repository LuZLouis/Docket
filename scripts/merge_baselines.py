#!/usr/bin/env python3
"""Merge measured AVSA comparison rows with RoFL/ACORN baseline rows."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence


OUT_COLUMNS = [
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


class MergeError(RuntimeError):
    pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--avsa", type=Path, required=True, help="analysis directory or comparison_avsa.csv")
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    avsa_rows = read_avsa(args.avsa)
    baseline_rows = read_baseline(args.baseline)
    merged = avsa_rows + baseline_rows
    if args.dry_run:
        print(f"avsa_rows={len(avsa_rows)} baseline_rows={len(baseline_rows)} merged_rows={len(merged)}")
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_csv(args.out, OUT_COLUMNS, merged)
    write_markdown(args.out.parent / "table_comparison_rofl_acorn.md", OUT_COLUMNS, merged, "AVSA, RoFL, and ACORN Comparison")
    write_latex(args.out.parent / "table_comparison_rofl_acorn.tex", OUT_COLUMNS, merged, "AVSA, RoFL, and ACORN Comparison")
    return 0


def read_avsa(path: Path) -> List[Dict[str, str]]:
    candidate = path / "comparison_avsa.csv" if path.is_dir() else path
    if not candidate.exists():
        raise MergeError(f"missing AVSA comparison CSV: {candidate}")
    rows = read_csv(candidate)
    out = []
    for row in rows:
        normalized = normalize_common(row)
        normalized["scheme"] = normalized["scheme"] or "AVSA"
        normalized["source"] = normalized["source"] or "measured_avsa"
        normalized["value_source"] = "measured_avsa"
        normalized["status"] = normalized["status"] or "measured"
        out.append(normalized)
    return out


def read_baseline(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise MergeError(f"missing baseline CSV: {path}")
    rows = read_csv(path)
    out = []
    for row in rows:
        normalized = normalize_common(row)
        status = normalized["status"].upper()
        value = normalized["value"].strip()
        source = normalized["source"].lower()
        if "synthetic" in source:
            normalized["value_source"] = "synthetic_fixture"
        elif status == "TODO" or value == "" or value.upper() == "TODO":
            normalized["value_source"] = "todo_baseline"
        else:
            normalized["value_source"] = "published_baseline"
        out.append(normalized)
    return out


def normalize_common(row: Dict[str, str]) -> Dict[str, str]:
    operation = row.get("operation", "")
    value = row.get("value", "")
    unit = row.get("unit", "")
    if not value and row.get("reported_runtime_ms"):
        value = row.get("reported_runtime_ms", "")
        unit = "ms"
    if not value and row.get("reported_comm_bytes"):
        value = row.get("reported_comm_bytes", "")
        unit = "bytes"
    return {
        "scheme": row.get("scheme", ""),
        "source": row.get("source", ""),
        "value_source": row.get("value_source", ""),
        "dataset": row.get("dataset") or row.get("model_or_dataset", ""),
        "dimension": row.get("dimension", ""),
        "predicate": row.get("predicate") or row.get("proof_type", ""),
        "operation": operation,
        "value": value,
        "value_std": row.get("value_std", ""),
        "unit": unit,
        "scope": row.get("scope", "per_client"),
        "backend": row.get("backend", ""),
        "n_selected": row.get("n_selected") or row.get("n_clients", ""),
        "case_name": row.get("case_name", ""),
        "notes": row.get("notes", ""),
        "citation_key": row.get("citation_key", ""),
        "status": row.get("status", ""),
    }


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


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
        handle.write("% Generated by scripts/merge_baselines.py.\n")
        handle.write("\\begin{table}[t]\n\\centering\n\\small\n")
        handle.write(f"\\caption{{{latex(title)}}}\n")
        handle.write("\\begin{tabular}{" + "l" * len(columns) + "}\n\\toprule\n")
        handle.write(" & ".join(latex(column) for column in columns) + " \\\\\n\\midrule\n")
        for row in rows:
            handle.write(" & ".join(latex(row.get(column, "")) for column in columns) + " \\\\\n")
        handle.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")


def latex(value: object) -> str:
    text = str(value)
    repl = {"\\": "\\textbackslash{}", "&": "\\&", "%": "\\%", "$": "\\$", "#": "\\#", "_": "\\_", "{": "\\{", "}": "\\}"}
    return "".join(repl.get(ch, ch) for ch in text)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MergeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
