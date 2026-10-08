#!/usr/bin/env python3
"""Plot measured one-record Docket crypto components; never label as full round."""

import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tables", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--replace", action="store_true", help="replace figures previously generated in --out")
    args = parser.parse_args()
    if args.out.exists() and not args.replace:
        parser.error(f"output already exists: {args.out}")
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.tables / "component_summary.csv").open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if any(row["source"] != "measured" or row["scope"] != "one-record-crypto-components" for row in rows):
        raise SystemExit("untrusted component source/scope")
    rows = sorted((r for r in rows if r["profile"] == "Native" and r["predicate"] == "range"), key=lambda r: int(r["dim"]))
    if len(rows) < 2:
        raise SystemExit("at least two native range dimensions required")
    if len({(row["source_sha256"], row["execution_threads"]) for row in rows}) != 1:
        raise SystemExit("component plot requires one code version and worker configuration")
    x = [int(row["dim"]) for row in rows]
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.7))
    phases = [("predicate_prove", "Range proof"), ("predicate_verify", "Range verification"),
              ("link_prove", "Binding proof"), ("link_verify", "Binding verification"),
              ("encoding", "Encoding"), ("public_bases", "Public bases")]
    bottom = [0.] * len(x)
    for field, label in phases:
        values = [float(row[f"median_{field}_ms"]) / 1000 for row in rows]
        axes[0].bar([str(d) for d in x], values, bottom=bottom, label=label)
        bottom = [a + b for a, b in zip(bottom, values)]
    other = [float(row["median_total_sequential_ms"]) / 1000 - subtotal for row, subtotal in zip(rows, bottom)]
    if any(value < -0.01 for value in other):
        raise SystemExit("phase sum exceeds total timer")
    axes[0].bar([str(d) for d in x], [max(0, value) for value in other], bottom=bottom, label="Other timed work")
    axes[0].set(xlabel="Vector dimension", ylabel="Measured one-record time (s)", title="Native range components")
    axes[0].legend(frameon=False, fontsize=8)
    for field, label, marker in (("commitments", "Input commitments", "o"),
                                 ("encoding", "Mask encoding", "s"),
                                 ("predicate", "Range proof", "^"),
                                 ("link", "Binding proof", "d")):
        axes[1].plot(x, [float(row[f"median_{field}_bytes"]) / 1e6 for row in rows], marker=marker, label=label)
    axes[1].set(xlabel="Vector dimension", ylabel="Serialized bytes (MB)")
    axes[1].legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(args.out / "one_record_crypto.png", dpi=220)
    fig.savefig(args.out / "one_record_crypto.pdf")
    plt.close(fig)
    print(f"figure written to {args.out}")


if __name__ == "__main__":
    main()
