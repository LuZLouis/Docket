#!/usr/bin/env python3
"""Export Docket measurements as tidy, source-labelled plotting tables.

This exporter never converts historical estimates or published baselines into
measured Docket protocol results. Failed and missing samples remain explicit.
"""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def median(values):
    return statistics.median(values) if values else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("runs", nargs="+", type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"output already exists: {args.out}")
    args.out.mkdir(parents=True)
    samples, phases, messages, attacks, groups = [], [], [], [], defaultdict(list)
    for directory in args.runs:
        environment = json.loads((directory / "environment.json").read_text(encoding="utf-8"))
        if environment.get("source") != "measured" or environment.get("input_source") != "synthetic_fixture":
            raise SystemExit(f"untrusted source in {directory}")
        for index, line in enumerate((directory / "raw.jsonl").read_text(encoding="utf-8").splitlines()):
            row = json.loads(line)
            config = row["config"]
            run_dir = directory / f"run-{index}"
            base = {
                "run_set": str(directory), "sample": index,
                "n": config["n"], "dim": config["dim"],
                "m": config["m"], "t": config["t"],
                "profile": config["profile"],
                "predicate": "norm" if config["norm"] is not None else "range",
                "source": row.get("source", ""),
                "input_source": row.get("input_source", ""),
                "status": row["status"],
                "attack_status": row.get("attack_status", "passed" if row.get("attack_passed") else "not_run"),
                "oracle_equal": row.get("oracle_equal", ""),
                "total_sequential_ms": row.get("total_sequential_ms", ""),
                "wire_transmission_bytes": row.get("wire_transmission_bytes", ""),
                "unique_public_storage_bytes": row.get("unique_public_storage_bytes", ""),
                "error": row.get("error", ""),
            }
            samples.append(base)
            if row["status"] != "success":
                continue
            if row.get("source") != "measured" or row.get("input_source") != "synthetic_fixture" or row.get("oracle_equal") is not True:
                raise SystemExit(f"incomplete successful sample in {directory} line {index + 1}")
            if base["attack_status"] not in ("passed", "not_run"):
                raise SystemExit(f"fault suite failed in {directory} line {index + 1}")
            key = (base["n"], base["dim"], base["m"], base["t"], base["profile"], base["predicate"])
            groups[key].append(base)
            for name, ms in row["role_phase_ms"].items():
                role, phase = name.split(".", 1)
                phases.append({**base, "role": role, "phase": phase, "time_ms": ms})
            traffic = json.loads((run_dir / "traffic.json").read_text(encoding="utf-8"))
            if sum(event["bytes"] for event in traffic) != row["wire_transmission_bytes"]:
                raise SystemExit(f"traffic total differs from raw sample: {run_dir}")
            public_objects = {tuple(event["digest"]): event["bytes"] for event in traffic if event["public"]}
            if sum(public_objects.values()) != row["unique_public_storage_bytes"]:
                raise SystemExit(f"public storage differs from raw sample: {run_dir}")
            category = defaultdict(lambda: {"sends": 0, "bytes": 0, "public_digests": {}, "allocated_unique_bytes": 0})
            seen_public = set()
            for event in traffic:
                item = category[event["category"]]
                item["sends"] += 1
                item["bytes"] += event["bytes"]
                if event["public"]:
                    digest = tuple(event["digest"])
                    item["public_digests"][digest] = event["bytes"]
                    if digest not in seen_public:
                        item["allocated_unique_bytes"] += event["bytes"]
                        seen_public.add(digest)
            if sum(item["allocated_unique_bytes"] for item in category.values()) != row["unique_public_storage_bytes"]:
                raise SystemExit(f"category allocation differs from global storage: {run_dir}")
            for name, item in category.items():
                messages.append({**base, "category": name, "sends": item["sends"],
                                 "transmission_bytes": item["bytes"],
                                 "category_unique_public_bytes": sum(item["public_digests"].values()),
                                 "allocated_unique_public_bytes": item["allocated_unique_bytes"]})
            attack_rows = json.loads((run_dir / "attacks.json").read_text(encoding="utf-8"))
            if base["attack_status"] == "passed" and (not attack_rows or not all(attack["passed"] for attack in attack_rows)):
                raise SystemExit(f"attack status inconsistent with outcomes: {run_dir}")
            if base["attack_status"] == "not_run" and attack_rows:
                raise SystemExit(f"unlabelled attack outcomes: {run_dir}")
            for attack in attack_rows:
                attacks.append({**base, **attack})

    summary = []
    for key, rows in sorted(groups.items()):
        totals = [x["total_sequential_ms"] for x in rows]
        summary.append({"n": key[0], "dim": key[1], "m": key[2], "t": key[3],
                        "profile": key[4], "predicate": key[5], "source": "measured",
                        "input_source": "synthetic_fixture", "scope": "sequential single-process",
                        "successful_repetitions": len(rows),
                        "median_sequential_ms": median(totals),
                        "min_sequential_ms": min(totals), "max_sequential_ms": max(totals),
                        "median_wire_bytes": median([x["wire_transmission_bytes"] for x in rows]),
                        "median_unique_public_bytes": median([x["unique_public_storage_bytes"] for x in rows])})
    sample_fields = ["run_set", "sample", "n", "dim", "m", "t", "profile", "predicate", "source", "input_source", "status", "attack_status", "oracle_equal", "total_sequential_ms", "wire_transmission_bytes", "unique_public_storage_bytes", "error"]
    write_csv(args.out / "samples.csv", samples, sample_fields)
    write_csv(args.out / "summary.csv", summary, ["n", "dim", "m", "t", "profile", "predicate", "source", "input_source", "scope", "successful_repetitions", "median_sequential_ms", "min_sequential_ms", "max_sequential_ms", "median_wire_bytes", "median_unique_public_bytes"])
    write_csv(args.out / "phases.csv", phases, sample_fields + ["role", "phase", "time_ms"])
    write_csv(args.out / "messages.csv", messages, sample_fields + ["category", "sends", "transmission_bytes", "category_unique_public_bytes", "allocated_unique_public_bytes"])
    write_csv(args.out / "attacks.csv", attacks, sample_fields + ["name", "expected_label", "actual_label", "passed", "detected", "evidence", "new_valid_releases", "time_ms", "bytes", "detail"])
    manifest = {"source": "measured", "input_source": "synthetic_fixture",
                "time_scope": "single-process sequential full protocol; fault cases timed separately",
                "units": {"time": "ms", "communication": "bytes"},
                "runs": [str(x) for x in args.runs], "sample_rows": len(samples),
                "successful_rows": sum(x["status"] == "success" for x in samples),
                "failed_rows": sum(x["status"] != "success" for x in samples)}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest))
    if manifest["failed_rows"]:
        raise SystemExit("failed samples retained in samples.csv")


if __name__ == "__main__":
    main()
