"""Load and override benchmark settings.

Precedence: CLI overrides > environment variables > settings.yaml defaults.
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _results_dir() -> Path:
    """Each run writes to its own `results_<YYYYmmdd_HHMMSS>/` directory.

    Set `BENCH_RESULTS_DIR` to reuse an existing one — required when re-running a
    subset of benchmarks (`-b ...`) so the report is rebuilt from the full set of
    raw results rather than just the ones re-run.
    """
    override = os.environ.get("BENCH_RESULTS_DIR")
    if override:
        p = Path(override)
        return p if p.is_absolute() else ROOT / p
    return ROOT / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


RESULTS_DIR = _results_dir()
GRAPHS_DIR = RESULTS_DIR / "graphs"


def load(path: Path | None = None) -> dict[str, Any]:
    path = path or (ROOT / "config" / "settings.yaml")
    with open(path) as fh:
        cfg = yaml.safe_load(fh)

    # Environment overrides for CI.
    if os.environ.get("BENCH_CI") in ("1", "true"):
        cfg["sizes"] = cfg["sizes_ci"]
        cfg["repeats"] = cfg.get("repeats_ci", 1)
        cfg["db_bulk_sizes"] = cfg.get("db_bulk_sizes_ci", cfg.get("db_bulk_sizes", []))
    if os.environ.get("BENCH_SIZES"):
        cfg["sizes"] = [int(x) for x in os.environ["BENCH_SIZES"].split(",")]
    if os.environ.get("BENCH_SEED"):
        cfg["seed"] = int(os.environ["BENCH_SEED"])
    if os.environ.get("BENCH_REPEATS"):
        cfg["repeats"] = int(os.environ["BENCH_REPEATS"])
    if os.environ.get("BENCH_DB_BULK_SIZES"):
        cfg["db_bulk_sizes"] = [int(x) for x in os.environ["BENCH_DB_BULK_SIZES"].split(",")]

    # Quick-run overrides (used for smoke tests / CI tuning).
    if os.environ.get("BENCH_CRUD_DURATION"):
        cfg["crud"]["duration_secs"] = float(os.environ["BENCH_CRUD_DURATION"])
    if os.environ.get("BENCH_CRUD_WARMUP"):
        cfg["crud"]["warmup_secs"] = float(os.environ["BENCH_CRUD_WARMUP"])
    if os.environ.get("BENCH_CRUD_CONCURRENCY"):
        cfg["crud"]["concurrency"] = int(os.environ["BENCH_CRUD_CONCURRENCY"])
    if os.environ.get("BENCH_CRUD_PREPOP"):
        cfg["crud"]["records_prepopulate"] = int(os.environ["BENCH_CRUD_PREPOP"])
    if os.environ.get("BENCH_QUERY_DURATION"):
        cfg["query"]["duration_secs"] = float(os.environ["BENCH_QUERY_DURATION"])
    if os.environ.get("BENCH_QUERY_ZONE_SIZE"):
        cfg["query"]["zone_size"] = int(os.environ["BENCH_QUERY_ZONE_SIZE"])
    if os.environ.get("BENCH_PROP_SAMPLES"):
        cfg["propagation"]["samples"] = int(os.environ["BENCH_PROP_SAMPLES"])

    return cfg


def enabled_systems(cfg: dict[str, Any]) -> list[str]:
    return [k for k, v in cfg["systems"].items() if v.get("enabled")]


def system_label(cfg: dict[str, Any], key: str) -> str:
    if key == "bind9_native":
        return "Native BIND9"
    return cfg["systems"].get(key, {}).get("label", key)
