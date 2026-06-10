#!/usr/bin/env python3
"""Generate paper-facing AVSA evaluation figures and LaTeX tables."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


COMMON_COLUMNS = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "admitted",
    "excluded",
    "dropped",
    "backend",
    "component",
    "operation",
    "time_ms",
    "size_bytes",
    "result_label",
]

TAG_COLUMNS = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "admitted",
    "non_admitted",
    "boundary_size",
    "certificate_mode",
    "operation",
    "time_ms",
    "size_bytes",
    "result_label",
]

APPEAL_COLUMNS = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "appeal_case",
    "operation",
    "time_ms",
    "size_bytes",
    "result_label",
    "expected_label",
    "passed",
]

MALICIOUS_COLUMNS = [
    "experiment",
    "run_id",
    "n",
    "dimension",
    "attack",
    "verifier",
    "expected_label",
    "actual_label",
    "detected",
    "passed",
    "time_ms",
    "size_bytes",
]

BASELINE_COLUMNS = [
    "experiment",
    "scheme",
    "source",
    "dataset",
    "dimension",
    "predicate",
    "operation",
    "baseline_value",
    "baseline_unit",
    "avsa_extra_value",
    "avsa_extra_unit",
    "overhead_percent",
    "total_with_avsa",
    "total_percent_of_baseline",
    "path",
    "notes",
]


def read_csv_optional(path: Path, required: Sequence[str]) -> List[dict]:
    if not path.exists():
        print(f"warning: missing input CSV, skipping: {path}", file=sys.stderr)
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [col for col in required if col not in (reader.fieldnames or [])]
        if missing:
            print(f"warning: {path} missing columns {missing}; skipping", file=sys.stderr)
            return []
        return list(reader)


def f(row: dict, key: str) -> float:
    try:
        value = float(row[key])
    except (KeyError, ValueError):
        return 0.0
    return value if math.isfinite(value) else 0.0


def i(row: dict, key: str) -> int:
    try:
        return int(row[key])
    except (KeyError, ValueError):
        return 0


def label_for_row(row: dict) -> str:
    dim = i(row, "dimension")
    n = i(row, "n")
    if dim == 19000:
        dataset = "MNIST"
    elif dim == 62000:
        dataset = "CIFAR10-S"
    elif dim == 273000:
        dataset = "CIFAR10-L"
    elif dim == 818000:
        dataset = "Shakespeare"
    else:
        dataset = f"d={dim}"
    return f"{dataset}\nn={n}"


def import_matplotlib():
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception as exc:
        print(f"warning: matplotlib unavailable; figures skipped ({exc})", file=sys.stderr)
        return None
    plt.rcParams.update(
        {
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 11,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 9,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    return plt


def save_figure(fig, out_base: Path, png: bool = False) -> List[Path]:
    out_base.parent.mkdir(parents=True, exist_ok=True)
    paths = [out_base.with_suffix(".pdf"), out_base.with_suffix(".svg")]
    for path in paths:
        fig.savefig(path, bbox_inches="tight")
    if png:
        png_path = out_base.with_suffix(".png")
        fig.savefig(png_path, bbox_inches="tight", dpi=240)
        paths.append(png_path)
    return paths


def plot_common_path(plt, rows: List[dict], figures: Path, png: bool) -> List[Path]:
    rows = [r for r in rows if r.get("operation") != "total_common_path"]
    if not rows:
        print("warning: common_path_overhead skipped: no component rows", file=sys.stderr)
        return []
    by_run: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_run[row["run_id"]].append(row)
    run_ids = list(by_run)
    components = ["transcript", "decision", "mask_tag", "aggregate"]
    colors = {
        "transcript": "#4C78A8",
        "decision": "#F58518",
        "mask_tag": "#54A24B",
        "aggregate": "#B279A2",
    }
    labels = [label_for_row(by_run[run_id][0]) for run_id in run_ids]
    x = list(range(len(run_ids)))
    bottoms = [0.0] * len(run_ids)
    fig, ax = plt.subplots(figsize=(max(6.5, len(run_ids) * 0.85), 3.4))
    for component in components:
        values = [
            sum(f(row, "time_ms") for row in by_run[run_id] if row.get("component") == component)
            for run_id in run_ids
        ]
        ax.bar(x, values, bottom=bottoms, label=component, color=colors[component], width=0.68)
        bottoms = [b + v for b, v in zip(bottoms, values)]
    ax.set_ylabel("Time (ms)")
    ax.set_xlabel("Configuration")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0)
    ax.set_yscale("log")
    ax.grid(axis="y", linestyle=":", linewidth=0.7, alpha=0.65)
    ax.legend(ncol=4, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    fig.tight_layout()
    return save_figure(fig, figures / "common_path_overhead", png)


def plot_tag_vs_opening(
    plt, rows: List[dict], figures: Path, metric: str, operations: Sequence[str], name: str, ylabel: str, png: bool
) -> List[Path]:
    rows = [r for r in rows if r.get("operation") in operations]
    if not rows:
        print(f"warning: {name} skipped: no rows", file=sys.stderr)
        return []
    by_mode: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_mode[row["certificate_mode"]].append(row)
    fig, ax = plt.subplots(figsize=(5.8, 3.2))
    styles = {"tag": ("#4C78A8", "o"), "opening": ("#E45756", "s")}
    for mode in ("tag", "opening"):
        mode_rows = sorted(by_mode.get(mode, []), key=lambda r: i(r, "boundary_size"))
        if not mode_rows:
            continue
        xs = [i(row, "boundary_size") for row in mode_rows]
        ys = [f(row, metric) for row in mode_rows]
        color, marker = styles[mode]
        ax.plot(xs, ys, marker=marker, linewidth=2.0, markersize=5, label=mode, color=color)
    ax.set_xlabel("Boundary pairs |A| x |D_s - A|")
    ax.set_ylabel(ylabel)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, linestyle=":", linewidth=0.7, alpha=0.65)
    ax.legend(frameon=False)
    fig.tight_layout()
    return save_figure(fig, figures / name, png)


def latex_escape(value: object) -> str:
    text = str(value)
    return (
        text.replace("\\", "\\textbackslash{}")
        .replace("&", "\\&")
        .replace("%", "\\%")
        .replace("$", "\\$")
        .replace("#", "\\#")
        .replace("_", "\\_")
        .replace("{", "\\{")
        .replace("}", "\\}")
    )


def write_latex_table(path: Path, columns: Sequence[str], rows: Iterable[dict], caption: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("% Auto-generated from AVSA evaluation CSVs.\n")
        handle.write("\\begin{table}[t]\n\\centering\n")
        handle.write(f"\\caption{{{latex_escape(caption)}}}\n")
        handle.write("\\begin{tabular}{" + "l" * len(columns) + "}\n")
        handle.write("\\toprule\n")
        handle.write(" & ".join(latex_escape(col) for col in columns) + " \\\\\n")
        handle.write("\\midrule\n")
        for row in rows:
            handle.write(" & ".join(latex_escape(row.get(col, "")) for col in columns) + " \\\\\n")
        handle.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")


def short_rows(rows: List[dict], columns: Sequence[str], limit: int = 24) -> List[dict]:
    return [{col: row.get(col, "") for col in columns} for row in rows[:limit]]


def write_tables(results: Path, tables: Path) -> List[Path]:
    generated: List[Path] = []
    appeal = read_csv_optional(results / "appeal_cost.csv", APPEAL_COLUMNS)
    if appeal:
        path = tables / "appeal_cost.tex"
        cols = ["dimension", "appeal_case", "operation", "time_ms", "size_bytes", "result_label", "passed"]
        write_latex_table(path, cols, short_rows(appeal, cols), "AVSA appeal and rejection audit costs.")
        generated.append(path)

    malicious = read_csv_optional(results / "malicious_server_detection.csv", MALICIOUS_COLUMNS)
    if malicious:
        path = tables / "malicious_server_detection.tex"
        cols = ["attack", "verifier", "expected_label", "actual_label", "detected", "passed"]
        write_latex_table(path, cols, short_rows(malicious, cols, limit=40), "Malicious aggregation-server detection labels.")
        generated.append(path)

    baseline = read_csv_optional(results / "baseline_overhead_percent.csv", BASELINE_COLUMNS)
    if baseline:
        common_rows = [row for row in baseline if row.get("path") == "common"]
        path = tables / "baseline_overhead_percent.tex"
        cols = ["scheme", "dataset", "predicate", "operation", "baseline_value", "avsa_extra_value", "overhead_percent", "baseline_unit"]
        write_latex_table(path, cols, short_rows(common_rows, cols, limit=36), "Common-path AVSA overhead over published SAIV baselines.")
        generated.append(path)
    return generated


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--figures", type=Path, default=Path("figures"))
    parser.add_argument("--tables", type=Path, default=Path("tables"))
    parser.add_argument("--png-preview", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    figures: List[Path] = []
    plt = import_matplotlib()
    if plt is not None:
        common = read_csv_optional(args.results / "common_path.csv", COMMON_COLUMNS)
        tag = read_csv_optional(args.results / "tag_vs_opening.csv", TAG_COLUMNS)
        if common:
            figures.extend(plot_common_path(plt, common, args.figures, args.png_preview))
        if tag:
            figures.extend(
                plot_tag_vs_opening(
                    plt,
                    tag,
                    args.figures,
                    "size_bytes",
                    ("maskcert_tag_generation", "maskcert_open_generation"),
                    "tag_vs_opening_size",
                    "Certificate size (bytes)",
                    args.png_preview,
                )
            )
            figures.extend(
                plot_tag_vs_opening(
                    plt,
                    tag,
                    args.figures,
                    "time_ms",
                    ("verify_mask_tag", "verify_mask_open"),
                    "tag_vs_opening_time",
                    "Verification time (ms)",
                    args.png_preview,
                )
            )
        plt.close("all")

    tables = write_tables(args.results, args.tables)
    print(f"generated {len(figures)} figure file(s) and {len(tables)} table file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
