"""Capture the test environment (hardware, OS, software/DB versions)."""
from __future__ import annotations

import platform
import shutil
import subprocess


def _cmd(args: list[str]) -> str:
    try:
        return subprocess.run(
            args, text=True, capture_output=True, timeout=15
        ).stdout.strip()
    except Exception:
        return ""


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


def _image_version(image: str) -> str:
    """Report the pinned image tag for a software component."""
    return image


def collect(cfg: dict) -> dict:
    import os

    total, used, free = shutil.disk_usage("/")
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
        "software": {
            # Image tags are the source of truth; keep in sync with systems/*/compose.yml.
            "bindizr": "bindizr:local (built from source)",
            "bind9": "internetsystemsconsortium/bind9:9.21",
            "powerdns": "powerdns/pdns-auth-49:latest",
            "technitium": "technitium/dns-server:latest",
            "mysql": "mysql:9.7",
            "postgresql": "postgres:17",
        },
        "config": {
            "seed": cfg.get("seed"),
            "sizes": cfg.get("sizes"),
            "crud_concurrency": cfg.get("crud", {}).get("concurrency"),
            "crud_duration_secs": cfg.get("crud", {}).get("duration_secs"),
            "repeats": int(os.environ.get("BENCH_REPEATS", "1")),
        },
        "limits": {
            # Per-SUT-container resource caps applied via compose deploy.resources.
            "cpus": os.environ.get("BENCH_CPU_LIMIT", "4"),
            "memory": os.environ.get("BENCH_MEM_LIMIT", "4g"),
        },
    }
