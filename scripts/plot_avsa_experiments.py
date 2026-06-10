#!/usr/bin/env python3
"""Generate paper-style AVSA experiment figures from analysis CSVs."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


class PlotError(RuntimeError):
    pass


DIM_ORDER = [8, 64, 1024, 19000, 62000, 273000, 818000]
BASELINE_COMPARISON_DIMS = {19000, 62000, 273000, 818000}
DATASET_BY_DIM = {
    8: "8",
    64: "64",
    1024: "1k",
    19000: "19k",
    62000: "62k",
    273000: "273k",
    818000: "818k",
}

STAGE_GROUPS = [
    ("Total", ["honest_full_audit_pipeline"]),
    ("Setup", ["round_generation", "commit_vector", "mask_tag_generation"]),
    ("Submit", ["submit_prove", "submit_verify"]),
    ("Input proof", ["signed_range_prove", "signed_range_verify", "l2_prove", "l2_verify"]),
    (
        "Decision",
        [
            "transcript_root_build",
            "membership_verify",
            "receipt_verify",
            "verify_accepted_decision",
            "verify_appeal",
        ],
    ),
    ("Mask/Aggregate", ["verify_mask_certificate", "verify_aggregate_certificate"]),
]

COMPARISON_GRID = [
    ("q_inf", "client_prove_time_per_client", "Client time (s)", r"Per-client proof $L_\infty$"),
    ("q_inf", "bandwidth_per_client", "Bandwidth (KB)", r"Per-client bandwidth $L_\infty$"),
    ("q_inf", "server_verify_time_per_client", "Verify time (s)", r"Server verifies per client $L_\infty$"),
    ("q_2", "client_prove_time_per_client", "Client time (s)", r"Per-client proof $L_2$"),
    ("q_2", "bandwidth_per_client", "Bandwidth (KB)", r"Per-client bandwidth $L_2$"),
    ("q_2", "server_verify_time_per_client", "Verify time (s)", r"Server verifies per client $L_2$"),
]

SCHEME_STYLE = {
    "RoFL": ("#6f58e9", "s"),
    "ACORN": ("#d72b7a", "o"),
    "AVSA": ("#f26b21", "^"),
    "AVSA derived": ("#f26b21", "^"),
}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="analysis directory")
    parser.add_argument("--out", type=Path, default=Path("figures"))
    parser.add_argument("--png-preview", action="store_true", help="also write PNG previews")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    runtime_path, comm_path, overhead_path, comparison_path = validate_input_dir(args.input)
    runtime = read_csv(runtime_path)
    comm = read_csv(comm_path)
    overhead = read_csv(overhead_path)
    comparison = read_csv(comparison_path)
    derived_client_scaling = read_csv(args.input / "table_client_scaling_derived.csv")
    if args.dry_run:
        print(
            f"runtime_rows={len(runtime)} comm_rows={len(comm)} "
            f"overhead_rows={len(overhead)} comparison_rows={len(comparison)} "
            f"derived_client_scaling_rows={len(derived_client_scaling)}"
        )
        return 0

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as error:
        print(f"warning: matplotlib unavailable; no plots generated: {error}", file=sys.stderr)
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    style(plt)
    generated: List[str] = []
    generated += plot_avsa_overhead_grid(runtime, "dim", args.out, plt, args.png_preview)
    generated += plot_avsa_overhead_grid(
        derived_client_scaling or runtime,
        "n_selected",
        args.out,
        plt,
        args.png_preview,
    )
    generated += plot_comparison_grid(comparison, args.out, plt, args.png_preview)
    print(f"generated {len(generated)} plot files")
    return 0


def validate_input_dir(root: Path) -> Tuple[Path, Path, Path, Path]:
    if not root.exists():
        raise PlotError(
            f"analysis input directory does not exist: {root}. "
            "Run scripts/analyze_avsa_experiments.py first."
        )
    runtime = root / "table_runtime_summary.csv"
    comm = root / "table_comm_summary.csv"
    overhead = root / "table_accountability_overhead.csv"
    comparison = root / "comparison_merged.csv"
    if not any(path.exists() for path in [runtime, comm, overhead, comparison]):
        raise PlotError(
            f"no analysis summary CSVs found under {root}. "
            "Expected table_runtime_summary.csv, table_comm_summary.csv, "
            "table_accountability_overhead.csv, or comparison_merged.csv."
        )
    return runtime, comm, overhead, comparison


def style(plt) -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.size": 10.5,
            "axes.labelsize": 11,
            "axes.titlesize": 12,
            "legend.fontsize": 9.5,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "axes.linewidth": 1.1,
            "lines.linewidth": 2.4,
            "lines.markersize": 6.5,
            "xtick.major.width": 1.0,
            "ytick.major.width": 1.0,
            "xtick.minor.width": 0.8,
            "ytick.minor.width": 0.8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def plot_avsa_overhead_grid(rows, x_col: str, out: Path, plt, png: bool) -> List[str]:
    stage_data = build_stage_data(rows, x_col)
    if not any(has_enough_points(series) for series in stage_data.values()):
        stem = "fig_avsa_overhead_by_dimension" if x_col == "dim" else "fig_avsa_overhead_by_clients"
        warn(f"{stem} skipped: insufficient {x_col} points")
        return []

    x_values = sorted(
        {
            x
            for series_by_label in stage_data.values()
            for points in series_by_label.values()
            for x, _, _ in points
        },
        key=lambda value: sort_key_for_x(value, x_col),
    )
    x_positions = {value: index for index, value in enumerate(x_values)}
    x_labels = [format_x_label(value, x_col) for value in x_values]

    fig, axes = plt.subplots(2, 3, figsize=(11.2, 5.7), sharex=True)
    axes_flat = list(axes.flat)
    handles = []
    labels = []
    letters = "abcdef"
    for index, ((title, _ops), ax) in enumerate(zip(STAGE_GROUPS, axes_flat)):
        ax.set_title(f"({letters[index]}) {title}")
        series = stage_data.get(title, {})
        for label, points in sorted(series.items()):
            points = sorted(points, key=lambda item: sort_key_for_x(item[0], x_col))
            xs = [x_positions[x] for x, _, _ in points]
            ys = [max(y, 1e-9) for _, y, _ in points]
            yerr = [err for _, _, err in points]
            color, marker = style_for_label(label)
            artist = ax.errorbar(
                xs,
                ys,
                yerr=yerr if any(err > 0 for err in yerr) else None,
                capsize=3 if any(err > 0 for err in yerr) else 0,
                marker=marker,
                color=color,
                label=label,
            )
            if label not in labels:
                handles.append(artist.lines[0])
                labels.append(label)
        ax.set_yscale("log")
        ax.grid(True, which="major", axis="y", color="#d9d9d9", linewidth=0.75)
        ax.grid(True, which="minor", axis="y", color="#eeeeee", linewidth=0.45)
        ax.set_xticks(range(len(x_values)))
        ax.set_xticklabels(x_labels)
        if index % 3 == 0:
            ax.set_ylabel("Time (ms)")
        if index >= 3:
            ax.set_xlabel("Dimension" if x_col == "dim" else "Selected clients")
    if handles:
        fig.legend(handles, labels, loc="upper center", ncol=min(4, len(labels)), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    stem = "fig_avsa_overhead_by_dimension" if x_col == "dim" else "fig_avsa_overhead_by_clients"
    return save_figure(fig, out, stem, png)


def build_stage_data(rows, x_col: str) -> Dict[str, Dict[str, List[Tuple[int, float, float]]]]:
    op_to_stage = {
        operation: title
        for title, operations in STAGE_GROUPS
        for operation in operations
    }
    grouped: Dict[Tuple[str, str, int], Dict[str, List[Tuple[float, float]]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        stage = op_to_stage.get(row.get("operation", ""))
        if not stage:
            continue
        x_value = to_int(row.get(x_col))
        if x_value <= 0:
            continue
        series = overhead_series_label(row, x_col)
        mean = to_float(row.get("mean_ms"))
        std = to_float(row.get("std_ms"))
        grouped[(stage, series, x_value)][row.get("operation", "")].append((mean, std))

    out: Dict[str, Dict[str, List[Tuple[int, float, float]]]] = defaultdict(lambda: defaultdict(list))
    for (stage, series, x_value), by_operation in grouped.items():
        mean_sum = 0.0
        variance_sum = 0.0
        for values in by_operation.values():
            op_mean = sum(value for value, _ in values)
            op_std = math.sqrt(sum(std * std for _, std in values))
            mean_sum += op_mean
            variance_sum += op_std * op_std
        out[stage][series].append((x_value, mean_sum, math.sqrt(variance_sum)))
    return out


def overhead_series_label(row: Dict[str, str], x_col: str) -> str:
    backend = row.get("backend", "AVSA")
    backend = "AVSA" if backend == "bulletproofs" else backend
    if x_col == "dim":
        return f"{backend}, n={row.get('n_selected')}"
    return f"{backend}, d={format_x_label(to_int(row.get('dim')), 'dim')}"


def plot_comparison_grid(rows, out: Path, plt, png: bool) -> List[str]:
    data = build_comparison_data(rows)
    if not data:
        warn("fig_comparison_rofl_acorn skipped: no comparison values")
        return []
    if not any(("AVSA" in panel or "AVSA derived" in panel) for panel in data.values()):
        warn("fig_comparison_rofl_acorn has no AVSA rows at 19k/62k/273k/818k; run aligned AVSA benchmarks to add them")

    fig, axes = plt.subplots(2, 3, figsize=(11.2, 5.7), sharex=True)
    handles = []
    labels = []
    letters = "abcdef"
    for index, (predicate, operation, ylabel, title) in enumerate(COMPARISON_GRID):
        ax = axes.flat[index]
        ax.set_title(f"({letters[index]}) {title}")
        panel = data.get((predicate, operation), {})
        dims = sorted(
            {dim for scheme_points in panel.values() for dim in scheme_points},
            key=lambda value: sort_key_for_x(value, "dim"),
        )
        if not dims:
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            continue
        x_positions = {dim: pos for pos, dim in enumerate(dims)}
        for scheme in ["RoFL", "ACORN", "AVSA", "AVSA derived"]:
            points = panel.get(scheme, {})
            if not points:
                continue
            xs = [x_positions[dim] for dim in dims if dim in points]
            ys = [max(points[dim][0], 1e-12) for dim in dims if dim in points]
            yerr = [points[dim][1] for dim in dims if dim in points]
            color, marker = SCHEME_STYLE.get(scheme, ("#333333", "o"))
            artist = ax.errorbar(
                xs,
                ys,
                yerr=yerr if any(err > 0 for err in yerr) else None,
                capsize=3 if any(err > 0 for err in yerr) else 0,
                marker=marker,
                color=color,
                linestyle="--" if scheme == "AVSA derived" else "-",
                markerfacecolor="white" if scheme == "AVSA derived" else color,
                label=scheme,
            )
            if scheme not in labels:
                handles.append(artist.lines[0])
                labels.append(scheme)
        ax.set_yscale("log")
        ax.grid(True, which="major", axis="y", color="#d9d9d9", linewidth=0.75)
        ax.grid(True, which="minor", axis="y", color="#eeeeee", linewidth=0.45)
        ax.set_xticks(range(len(dims)))
        ax.set_xticklabels([format_x_label(dim, "dim") for dim in dims])
        if index % 3 == 0:
            ax.set_ylabel(ylabel)
        else:
            ax.set_ylabel(ylabel)
        if index >= 3:
            ax.set_xlabel("Dimension")
    if handles:
        fig.legend(handles, labels, loc="upper center", ncol=len(labels), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    return save_figure(fig, out, "fig_comparison_rofl_acorn", png)


def build_comparison_data(rows) -> Dict[Tuple[str, str], Dict[str, Dict[int, Tuple[float, float]]]]:
    out: Dict[Tuple[str, str], Dict[str, Dict[int, Tuple[float, float]]]] = defaultdict(lambda: defaultdict(dict))
    for row in rows:
        if row.get("status", "").upper() == "TODO":
            continue
        predicate = row.get("predicate", "")
        operation = row.get("operation", "")
        if (predicate, operation) not in {(p, o) for p, o, _, _ in COMPARISON_GRID}:
            continue
        scheme = normalize_scheme(row.get("scheme", ""))
        if scheme == "AVSA" and row.get("value_source", "").startswith("derived"):
            scheme = "AVSA derived"
        if scheme not in {"RoFL", "ACORN", "AVSA", "AVSA derived"}:
            continue
        dim = to_int(row.get("dimension"))
        value = normalize_comparison_value(row)
        if dim not in BASELINE_COMPARISON_DIMS or value <= 0:
            continue
        std = normalize_comparison_std(row)
        out[(predicate, operation)][scheme][dim] = (value, std)
    return out


def normalize_scheme(value: str) -> str:
    lowered = value.lower()
    if lowered == "rofl":
        return "RoFL"
    if lowered == "acorn":
        return "ACORN"
    if lowered == "avsa":
        return "AVSA"
    return value


def normalize_comparison_value(row: Dict[str, str]) -> float:
    value = to_float(row.get("value"))
    unit = row.get("unit", "").lower()
    operation = row.get("operation", "")
    if operation == "bandwidth_per_client":
        if unit in {"bytes", "byte"}:
            return value / 1024.0
        if unit in {"mb", "mib"}:
            return value * 1024.0
        return value
    if unit in {"ms", "millisecond", "milliseconds"}:
        return value / 1000.0
    return value


def normalize_comparison_std(row: Dict[str, str]) -> float:
    std = to_float(row.get("value_std"))
    if std <= 0:
        return 0.0
    unit = row.get("unit", "").lower()
    operation = row.get("operation", "")
    if operation == "bandwidth_per_client":
        if unit in {"bytes", "byte"}:
            return std / 1024.0
        if unit in {"mb", "mib"}:
            return std * 1024.0
        return std
    if unit in {"ms", "millisecond", "milliseconds"}:
        return std / 1000.0
    return std


def save_figure(fig, out: Path, stem: str, png: bool) -> List[str]:
    written: List[str] = []
    for ext in ["pdf", "svg"] + (["png"] if png else []):
        path = out / f"{stem}.{ext}"
        fig.savefig(path, bbox_inches="tight")
        written.append(path.name)
    fig.clf()
    return written


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def has_enough_points(series: Dict[str, List[Tuple[int, float, float]]]) -> bool:
    return any(len({x for x, _, _ in points}) >= 2 for points in series.values())


def style_for_label(label: str) -> Tuple[str, str]:
    if "mock" in label:
        return "#777777", "x"
    dim_styles = [
        ("d=8", "#2f7ebc", "o"),
        ("d=64", "#f26b21", "^"),
        ("d=1k", "#2ca25f", "s"),
        ("d=19k", "#8b5cf6", "D"),
        ("d=62k", "#d72b7a", "o"),
        ("d=273k", "#7f7f7f", "s"),
        ("d=818k", "#111111", "^"),
    ]
    for needle, color, marker in dim_styles:
        if needle in label:
            return color, marker
    if "n=50" in label:
        return "#f26b21", "^"
    if "n=16" in label:
        return "#2f7ebc", "o"
    if "AVSA" in label:
        return "#f26b21", "^"
    return "#4c4c4c", "s"


def sort_key_for_x(value: int, x_col: str = "dim") -> Tuple[int, int]:
    if x_col == "dim" and value in DIM_ORDER:
        return (DIM_ORDER.index(value), value)
    return (len(DIM_ORDER), value)


def format_x_label(value: int, x_col: str) -> str:
    if x_col == "dim":
        return DATASET_BY_DIM.get(value, f"{value // 1000}k" if value >= 1000 else str(value))
    return str(value)


def to_float(value: Optional[str]) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


def to_int(value: Optional[str]) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PlotError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
