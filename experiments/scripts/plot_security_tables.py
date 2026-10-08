#!/usr/bin/env python3
"""Plot only locally measured Docket full-round CSVs; export PNG and PDF."""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def read(path):
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def save(fig, directory, name):
    fig.tight_layout()
    fig.savefig(directory / f"{name}.png", dpi=220)
    fig.savefig(directory / f"{name}.pdf")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tables", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--replace", action="store_true", help="replace figures previously generated in --out")
    args = parser.parse_args()
    if args.out.exists() and not args.replace:
        parser.error(f"output already exists: {args.out}")
    args.out.mkdir(parents=True, exist_ok=True)
    summary = read(args.tables / "summary.csv")
    samples = read(args.tables / "samples.csv")
    if any(row["source"] != "measured" or row["scope"] != "sequential single-process" for row in summary):
        raise SystemExit("untrusted summary source/scope")
    if any(row["status"] != "success" for row in samples):
        raise SystemExit("failed samples exist; inspect samples.csv before plotting")
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

    client = sorted((r for r in summary if r["profile"] == "Native" and r["predicate"] == "range" and int(r["dim"]) == 8), key=lambda r: int(r["n"]))
    if len(client) >= 2:
        n = [int(r["n"]) for r in client]
        fig, axes = plt.subplots(1, 2, figsize=(9, 3.5))
        axes[0].plot(n, [float(r["median_sequential_ms"]) / 1000 for r in client], "o-")
        axes[0].set(xlabel="Clients n", ylabel="Sequential full-round time (s)", title="Native, range, dimension 8")
        axes[1].plot(n, [float(r["median_wire_bytes"]) / 1e6 for r in client], "o-", label="All sends")
        axes[1].plot(n, [float(r["median_unique_public_bytes"]) / 1e6 for r in client], "s--", label="Unique public objects")
        axes[1].set(xlabel="Clients n", ylabel="Encoded bytes (MB)")
        axes[1].legend(frameon=False)
        save(fig, args.out, "clients_full_round")

    dimension = sorted((r for r in summary if r["profile"] == "Native" and r["predicate"] == "range" and int(r["n"]) == 4), key=lambda r: int(r["dim"]))
    if len(dimension) >= 2:
        d = [int(r["dim"]) for r in dimension]
        fig, axes = plt.subplots(1, 2, figsize=(9, 3.5))
        axes[0].plot(d, [float(r["median_sequential_ms"]) / 1000 for r in dimension], "o-")
        axes[0].set(xlabel="Vector dimension", ylabel="Sequential full-round time (s)", title="Native, range, n=4")
        axes[1].plot(d, [float(r["median_wire_bytes"]) / 1e6 for r in dimension], "o-", label="All sends")
        axes[1].plot(d, [float(r["median_unique_public_bytes"]) / 1e6 for r in dimension], "s--", label="Unique public objects")
        axes[1].set(xlabel="Vector dimension", ylabel="Encoded bytes (MB)")
        axes[1].legend(frameon=False)
        save(fig, args.out, "dimensions_full_round")

    paired = defaultdict(dict)
    for row in summary:
        paired[(int(row["n"]), int(row["dim"]), row["predicate"])][row["profile"]] = row
    paired = [(key, group) for key, group in sorted(paired.items()) if "Native" in group and "Additive" in group]
    if paired:
        labels = [f"n={key[0]}, d={key[1]}, {key[2]}" for key, _ in paired]
        x = list(range(len(labels)))
        fig, axes = plt.subplots(1, 2, figsize=(max(8, len(x) * 3), 3.8))
        for ax, field, scale, unit in ((axes[0], "median_sequential_ms", 1000, "Sequential time (s)"),
                                       (axes[1], "median_wire_bytes", 1e6, "All encoded sends (MB)")):
            for offset, profile, color in ((-0.18, "Native", "#3465a4"), (0.18, "Additive", "#d07031")):
                ax.bar([p + offset for p in x], [float(group[profile][field]) / scale for _, group in paired], width=0.34, color=color, label=profile)
            ax.set_xticks(x, labels, rotation=15, ha="right")
            ax.set_ylabel(unit)
            ax.legend(frameon=False)
        save(fig, args.out, "matched_profiles")

        phase_rows = read(args.tables / "phases.csv")
        by_sample = defaultdict(lambda: defaultdict(float))
        for row in phase_rows:
            key = (int(row["n"]), int(row["dim"]), row["predicate"], row["profile"], row["run_set"], row["sample"])
            by_sample[key][row["role"]] += float(row["time_ms"]) / 1000
        bars = [(key, profile) for key, _ in paired for profile in ("Native", "Additive")]
        roles = ("setup", "client", "server", "holder", "log", "auditor")
        fig, ax = plt.subplots(figsize=(max(8, len(bars) * 2), 3.8))
        bottoms = [0.] * len(bars)
        for role in roles:
            heights = []
            for key, profile in bars:
                samples_for_bar = [parts for (n, dim, predicate, p, _, _), parts in by_sample.items()
                                   if (n, dim, predicate, p) == (*key, profile)]
                heights.append(statistics.median(parts.get(role, 0.) for parts in samples_for_bar))
            ax.bar(range(len(bars)), heights, bottom=bottoms, label=role.title())
            bottoms = [a + b for a, b in zip(bottoms, heights)]
        ax.set_xticks(range(len(bars)), [f"n={key[0]}, d={key[1]}\n{key[2]}, {profile}" for key, profile in bars], rotation=15, ha="right")
        ax.set_ylabel("Median role time (s), sequential execution")
        ax.legend(frameon=False, ncol=3)
        save(fig, args.out, "role_breakdown")

    attacks = read(args.tables / "attacks.csv")
    appeal_names = ("omission_appeal", "false_reject_appeal", "appeal_resolution_full_replay")
    appeals = [a for a in attacks if a["name"] in appeal_names]
    if appeals:
        costs = defaultdict(list)
        for row in appeals:
            costs[row["name"]].append(float(row["time_ms"]))
        names = [n for n in appeal_names if n in costs]
        fig, ax = plt.subplots(figsize=(7, 3.5))
        ax.boxplot([costs[n] for n in names], tick_labels=[n.replace("_", "\n") for n in names], showfliers=True)
        ax.set(ylabel="Real verification time (ms)", title="Appeal and resolution operations")
        save(fig, args.out, "appeal_operations")
    print(f"plots written to {args.out}")


if __name__ == "__main__":
    main()
