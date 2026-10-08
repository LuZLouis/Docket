#!/usr/bin/env python3
"""Run a bounded, serial Docket protocol experiment grid with explicit failures."""

import argparse
import csv
import json
import os
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="CSV with n,dim,profile,predicate,repetitions,warmup,attacks,timeout_seconds")
    parser.add_argument("--out", required=True, type=Path, help="new output directory")
    executable = "docket_real.exe" if os.name == "nt" else "docket_real"
    parser.add_argument("--binary", type=Path, default=Path("target/release") / executable)
    args = parser.parse_args()
    if args.out.exists():
        parser.error(f"output already exists: {args.out}")
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    plan = list(csv.DictReader(args.plan.open(newline="", encoding="utf-8")))
    args.out.mkdir(parents=True)
    (args.out / "plan.csv").write_bytes(args.plan.read_bytes())
    log = []
    for index, point in enumerate(plan):
        name = f"point-{index:02d}-{point['profile']}-{point['predicate']}-n{point['n']}-d{point['dim']}"
        path = args.out / name
        command = [str(args.binary.resolve()), "--n", point["n"], "--dim", point["dim"],
                   "--profile", point["profile"], "--predicate", point["predicate"],
                   "--warmup", point["warmup"], "--repetitions", point["repetitions"],
                   "--attacks", point["attacks"], "--out", str(path)]
        print(f"START {name}", flush=True)
        start = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=int(point["timeout_seconds"]), check=False)
            status = "success" if result.returncode == 0 else "failed"
            output = result.stdout + result.stderr
            exit_code = result.returncode
        except subprocess.TimeoutExpired as error:
            status, exit_code = "timeout", None
            output = ((error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or ""))
            output += ((error.stderr or b"").decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or ""))
        elapsed = time.monotonic() - start
        path.mkdir(exist_ok=True)
        (path / "driver.log").write_text(output, encoding="utf-8")
        expected = int(point["repetitions"])
        raw = path / "raw.jsonl"
        recorded = len(raw.read_text(encoding="utf-8").splitlines()) if raw.exists() else 0
        if recorded < expected:
            with raw.open("a", encoding="utf-8") as file:
                for missing in range(recorded, expected):
                    config = {"n": int(point["n"]), "dim": int(point["dim"]),
                              "m": 4, "t": 3, "profile": point["profile"].title(),
                              "norm": int(point["dim"]) * 9 if point["predicate"] == "norm" else None}
                    file.write(json.dumps({"status": status if status != "success" else "missing",
                                           "config": config, "sample": missing,
                                           "error": f"driver exit={exit_code}; elapsed_seconds={elapsed:.3f}"}) + "\n")
        entry = {**point, "name": name, "status": status, "exit_code": exit_code,
                 "driver_elapsed_seconds": round(elapsed, 3), "recorded_samples": recorded,
                 "output": str(path)}
        log.append(entry)
        (args.out / "driver_manifest.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
        print(f"{status.upper()} {name} {elapsed:.1f}s ({recorded}/{expected} measured rows)", flush=True)
    if any(item["status"] != "success" for item in log):
        raise SystemExit("one or more points failed or timed out; see driver_manifest.json")


if __name__ == "__main__":
    main()
