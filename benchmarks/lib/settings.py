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
    """Choose `results_<YYYYmmdd_HHMMSS>/`, or reuse `BENCH_RESULTS_DIR` for subset reruns."""
    override = os.environ.get("BENCH_RESULTS_DIR")
    if override:
        path = Path(override)
        return path if path.is_absolute() else ROOT / path
    return ROOT / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


RESULTS_DIR = _results_dir()
GRAPHS_DIR = RESULTS_DIR / "graphs"


def load(path: Path | None = None) -> dict[str, Any]:
    """Load benchmark settings and apply environment overrides."""
    path = path or (ROOT / "config" / "settings.yaml")

    with open(path) as file:
        config = yaml.safe_load(file)

    if os.environ.get("BENCH_CI") in ("1", "true"):
        config["sizes"] = config["sizes_ci"]
        config["repeats"] = config.get("repeats_ci", 1)
        config["db_bulk_sizes"] = config.get("db_bulk_sizes_ci", config.get("db_bulk_sizes", []))
        config["ixfr_baseline"] = config.get("ixfr_baseline_ci", config.get("ixfr_baseline"))
        config["ixfr_change_sizes"] = config.get(
            "ixfr_change_sizes_ci", config.get("ixfr_change_sizes", []))

    # Explicit environment values override the CI defaults selected above.
    if os.environ.get("BENCH_SIZES"):
        config["sizes"] = [int(size) for size in os.environ["BENCH_SIZES"].split(",")]

    if os.environ.get("BENCH_SEED"):
        config["seed"] = int(os.environ["BENCH_SEED"])

    if os.environ.get("BENCH_REPEATS"):
        config["repeats"] = int(os.environ["BENCH_REPEATS"])

    if os.environ.get("BENCH_DB_BULK_SIZES"):
        config["db_bulk_sizes"] = [int(size) for size in os.environ["BENCH_DB_BULK_SIZES"].split(",")]

    # Quick-run overrides (used for smoke tests / CI tuning).
    if os.environ.get("BENCH_CRUD_DURATION"):
        config["crud"]["duration_secs"] = float(os.environ["BENCH_CRUD_DURATION"])

    if os.environ.get("BENCH_CRUD_WARMUP"):
        config["crud"]["warmup_secs"] = float(os.environ["BENCH_CRUD_WARMUP"])

    if os.environ.get("BENCH_CRUD_CONCURRENCY"):
        config["crud"]["concurrency"] = int(os.environ["BENCH_CRUD_CONCURRENCY"])

    if os.environ.get("BENCH_CRUD_PREPOP"):
        config["crud"]["records_prepopulate"] = int(os.environ["BENCH_CRUD_PREPOP"])

    if os.environ.get("BENCH_QUERY_DURATION"):
        config["query"]["duration_secs"] = float(os.environ["BENCH_QUERY_DURATION"])

    if os.environ.get("BENCH_QUERY_ZONE_SIZE"):
        config["query"]["zone_size"] = int(os.environ["BENCH_QUERY_ZONE_SIZE"])

    if os.environ.get("BENCH_PROP_SAMPLES"):
        config["propagation"]["samples"] = int(os.environ["BENCH_PROP_SAMPLES"])

    return config


def system_label(config: dict[str, Any], key: str) -> str:
    """Return the display label for a benchmark system."""
    if key == "bind9_native":
        return "Native BIND9"
    return config["systems"].get(key, {}).get("label", key)
