#!/usr/bin/env python3
"""Print bench_avsa commands from Round 10 experiment TOML configs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 only.
    tomllib = None


DEFAULT_CONFIGS = [
    Path("experiments/configs/avsa_internal_overhead.toml"),
    Path("experiments/configs/scale_clients.toml"),
    Path("experiments/configs/scale_dimension.toml"),
    Path("experiments/configs/rofl_acorn_aligned.toml"),
]


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        action="append",
        help="TOML config to expand. Defaults to all Round 10 configs.",
    )
    parser.add_argument(
        "--include-heavy",
        action="store_true",
        help="include cases marked heavy=true",
    )
    parser.add_argument(
        "--release",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="emit cargo run --release commands",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    configs = args.config or DEFAULT_CONFIGS
    commands: List[str] = []
    for config in configs:
        commands.extend(commands_for_config(config, args.include_heavy, args.release))
    for command in commands:
        print(command)
    return 0


def commands_for_config(path: Path, include_heavy: bool, release: bool) -> List[str]:
    data = load_config(path)
    experiment = data.get("experiment", {})
    defaults = data.get("defaults", {})
    cases = data.get("cases", [])
    backend = experiment.get("backend", defaults.get("backend", "bulletproofs"))
    features = experiment.get("cargo_features", "bulletproofs")
    derived_only = experiment.get("measurement_mode") == "derived_linear_model"

    commands = []
    for case in cases:
        if case.get("heavy") and not include_heavy:
            continue
        if derived_only or case.get("derived"):
            commands.append(
                f"# {path}: case {case.get('name', '<unnamed>')} is derived by analysis; no benchmark command emitted."
            )
            continue
        merged = merge(defaults, case)
        dim = int(merged["dim"])
        preset = preset_for_dimension(dim)
        cargo = ["cargo", "run"]
        if release:
            cargo.append("--release")
        if features:
            cargo.extend(["--features", str(features)])
        cargo.extend(["--bin", "bench_avsa", "--"])
        bench = [
            "--preset",
            preset,
            "--backend",
            str(backend),
            "--n-selected",
            str(merged["n_selected"]),
            "--n-admitted",
            str(merged["n_admitted"]),
            "--n-dropped",
            str(merged["n_dropped"]),
            "--n-rejected",
            str(merged.get("n_rejected", 0)),
            "--dim",
            str(dim),
            "--b-inf",
            str(merged["b_inf"]),
            "--b2-sq",
            str(merged["b2_sq"]),
            "--bit-size",
            str(merged["bit_size"]),
            "--iters",
            str(merged["iters"]),
            "--warmup",
            str(merged["warmup"]),
            "--seed",
            str(merged.get("seed", 42)),
            "--out",
            str(merged["out"]),
        ]
        commands.append(" ".join(cargo + bench))
    return commands


def load_config(path: Path) -> Dict[str, Any]:
    if tomllib is not None:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    return parse_simple_toml(path)


def parse_simple_toml(path: Path) -> Dict[str, Any]:
    """Small fallback parser for the repository's experiment config shape."""

    data: Dict[str, Any] = {"cases": []}
    current: Dict[str, Any] | None = None
    skip_multiline_array = False
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if skip_multiline_array:
                if "]" in line:
                    skip_multiline_array = False
                continue
            if line == "[[cases]]":
                case: Dict[str, Any] = {}
                data["cases"].append(case)
                current = case
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line.strip("[]")
                data.setdefault(section, {})
                current = data[section]
                continue
            if current is None or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if value.startswith("[") and not value.endswith("]"):
                skip_multiline_array = True
                continue
            current[key] = parse_value(value)
    return data


def parse_value(value: str) -> Any:
    value = value.strip().rstrip(",")
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_value(part.strip()) for part in inner.split(",") if part.strip()]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def merge(defaults: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(defaults)
    out.update(case)
    if "n_selected" not in out:
        raise ValueError(f"case {case.get('name', '<unnamed>')} missing n_selected")
    if "n_admitted" not in out:
        out["n_admitted"] = max(1, int(out["n_selected"]) - int(out.get("n_dropped", 0)))
    out.setdefault("n_dropped", 0)
    out.setdefault("n_rejected", 0)
    return out


def preset_for_dimension(dim: int) -> str:
    return {
        8: "smoke",
        64: "small",
        1024: "medium",
        19000: "mnist_like",
        62000: "cifar10_s_like",
        273000: "cifar10_l_like",
        818000: "shakespeare_like",
    }.get(dim, "medium")


if __name__ == "__main__":
    raise SystemExit(main())
