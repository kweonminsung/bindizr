"""Capture the test environment (hardware, OS, software/DB versions)."""
from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import yaml

SYSTEMS_DIR = Path(__file__).resolve().parent.parent / "systems"


def _cmd(args: list[str]) -> str:
    try:
        return subprocess.run(
            args, text=True, capture_output=True, timeout=15
        ).stdout.strip()
    except Exception:
        return ""


def _compose_images() -> dict[str, str]:
    """Image tag per service across systems/*/compose.yml, derived so the report
    cannot drift from what the stack runs. `seed` containers are scaffolding."""
    images: dict[str, str] = {}
    for compose in sorted(SYSTEMS_DIR.glob("*/compose.yml")):
        try:
            with open(compose) as fh:
                services = (yaml.safe_load(fh) or {}).get("services") or {}
        except Exception:
            continue
        for name, service in services.items():
            image = (service or {}).get("image")
            if image and name != "seed":
                images[name] = image
    if "bindizr" in images:
        images["bindizr"] += " (built from source)"
    return dict(sorted(images.items()))


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _mem_total_gb() -> float:
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    return round(kb / 1024 / 1024, 1)
    except OSError:
        pass
    return 0.0


def collect(cfg: dict) -> dict:
    import os

    free = shutil.disk_usage("/").free
    return {
        "hardware": {
            "cpu": _cpu_model(),
            "cpu_cores": os.cpu_count(),
            "memory_gb": _mem_total_gb(),
            "storage_free_gb": round(free / 1024**3, 1),
        },
        "os": {
            "platform": platform.platform(),
            "kernel": platform.release(),
        },
        "docker": {
            "version": _cmd(["docker", "version", "--format", "{{.Server.Version}}"]),
            "compose": _cmd(["docker", "compose", "version", "--short"]),
        },
        "software": _compose_images(),
        "config": {
            "seed": cfg.get("seed"),
            "sizes": cfg.get("sizes"),
            "crud_concurrency": cfg.get("crud", {}).get("concurrency"),
            "crud_duration_secs": cfg.get("crud", {}).get("duration_secs"),
            "repeats": int(cfg.get("repeats", 1)),
        },
        "limits": {
            # Per-SUT-container resource caps applied via compose deploy.resources.
            "cpus": os.environ.get("BENCH_CPU_LIMIT", "4"),
            "memory": os.environ.get("BENCH_MEM_LIMIT", "4g"),
        },
    }
