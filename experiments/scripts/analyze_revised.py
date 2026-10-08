#!/usr/bin/env python3
"""Summarize only complete measured Docket protocol runs; retain failures."""
import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", type=Path, help="docket_real output directories")
    args = parser.parse_args()
    groups = defaultdict(list)
    failures = []
    for directory in args.runs:
        for line in (directory / "raw.jsonl").read_text(encoding="utf8").splitlines():
            row = json.loads(line)
            if row.get("status") != "success":
                failures.append({"directory": str(directory), "row": row})
                continue
            if row.get("source") != "measured" or row.get("input_source") != "synthetic_fixture" or not row.get("attack_passed") or not row.get("oracle_equal"):
                raise SystemExit(f"untrusted/incomplete row in {directory}")
            c = row["config"]
            key = (c["n"], c["m"], c["t"], c["dim"], c["profile"], c["norm"] is not None)
            groups[key].append(row)
    for key, rows in sorted(groups.items()):
        times = [r["total_sequential_ms"] for r in rows]
        transmitted = [r["wire_transmission_bytes"] for r in rows]
        public = [r["unique_public_storage_bytes"] for r in rows]
        print(json.dumps({"config": key, "successful_repetitions": len(rows), "median_sequential_ms": statistics.median(times), "min_sequential_ms": min(times), "max_sequential_ms": max(times), "median_transmitted_bytes": statistics.median(transmitted), "median_unique_public_bytes": statistics.median(public), "source": "measured", "scope": "sequential single-process; synthetic signed inputs"}))
    for failure in failures:
        print(json.dumps({"failed_sample": failure}))
    if failures:
        raise SystemExit(f"{len(failures)} failed samples; no silent omission")


if __name__ == "__main__":
    main()
