#!/usr/bin/env python3
"""Export real one-record cryptographic measurements, separate from full rounds."""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def write(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("runs", nargs="+", type=Path)
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"output already exists: {args.out}")
    args.out.mkdir(parents=True)
    rows, groups = [], defaultdict(list)
    for directory in args.runs:
        scope = json.loads((directory / "scope.json").read_text(encoding="utf-8"))
        if scope.get("source") != "measured" or "one client" not in scope.get("scope", ""):
            raise SystemExit(f"invalid component source or scope: {directory}")
        for line in (directory / "raw.jsonl").read_text(encoding="utf-8").splitlines():
            sample = json.loads(line)
            row = {"run_set": str(directory), "sample": sample["sample"],
                   "dim": sample["dim"], "profile": sample["profile"],
                   "predicate": sample["predicate_name"], "status": sample["status"],
                   "source": sample.get("source", ""),
                   "scope": "one-record-crypto-components", "source_sha256": scope["source_sha256"],
                   "execution_threads": scope.get("execution_threads", "serial"),
                   "error": sample.get("error", ""),
                   "total_sequential_ms": sample.get("total_sequential_ms", "")}
            for name, value in sample.get("phase_ms", {}).items():
                row[f"{name}_ms"] = value
            for name, value in sample.get("serialized_bytes", {}).items():
                row[f"{name}_bytes"] = value
            rows.append(row)
            if sample["status"] == "success":
                if sample.get("source") != "measured" or sample.get("input_source") != "synthetic_fixture":
                    raise SystemExit(f"invalid measured row: {directory}")
                groups[(row["dim"], row["profile"], row["predicate"], row["source_sha256"], row["execution_threads"])].append(row)
    fields = ["run_set", "sample", "dim", "profile", "predicate", "status", "source", "scope", "source_sha256", "execution_threads", "error", "total_sequential_ms"]
    fields += [f"{name}_ms" for name in ("public_bases", "encoding", "predicate_prove", "link_prove", "predicate_verify", "link_verify")]
    fields += [f"{name}_bytes" for name in ("commitments", "encoding", "predicate", "link", "combined")]
    write(args.out / "component_samples.csv", rows, fields)
    summary = []
    for (dim, profile, predicate, source_sha256, execution_threads), sample in sorted(groups.items()):
        entry = {"dim": dim, "profile": profile, "predicate": predicate,
                 "successful_repetitions": len(sample), "source": "measured",
                 "scope": "one-record-crypto-components", "source_sha256": source_sha256,
                 "execution_threads": execution_threads}
        for field in fields[11:]:
            entry[f"median_{field}"] = statistics.median(float(row[field]) for row in sample)
        summary.append(entry)
    write(args.out / "component_summary.csv", summary,
          ["dim", "profile", "predicate", "successful_repetitions", "source", "scope", "source_sha256", "execution_threads"] +
          [f"median_{field}" for field in fields[11:]])
    failures = sum(row["status"] != "success" for row in rows)
    (args.out / "manifest.json").write_text(json.dumps({"source": "measured", "scope": "one-record-crypto-components", "runs": [str(x) for x in args.runs], "samples": len(rows), "failed_samples": failures}, indent=2), encoding="utf-8")
    print(f"exported {len(rows)} component samples; {failures} failures")
    if failures:
        raise SystemExit("failed samples retained in component_samples.csv")


if __name__ == "__main__":
    main()
