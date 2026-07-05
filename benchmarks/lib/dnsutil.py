"""DNS-plane helpers: query latency, AXFR timing/size, propagation polling.

Uses `dig` from the host (dnsutils) so behaviour matches what an operator would
observe. All queries target a resolver address:port.
"""
from __future__ import annotations

import subprocess
import time


def dig(name: str, rtype: str, server: str, port: int, tcp: bool = False,
        timeout: int = 5) -> tuple[bool, float, str]:
    """Return (answered, latency_secs, raw_output)."""
    args = ["dig", f"@{server}", "-p", str(port), name, rtype, "+tries=1",
            f"+time={timeout}", "+short"]
    if tcp:
        args.append("+tcp")
    t0 = time.monotonic()
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout + 2)
        dt = time.monotonic() - t0
        out = p.stdout.strip()
        return (bool(out), dt, out)
    except subprocess.TimeoutExpired:
        return (False, time.monotonic() - t0, "")


def axfr(zone: str, server: str, port: int, timeout: int = 300) -> tuple[float, int, int]:
    """Full zone transfer. Return (transfer_secs, record_count, bytes)."""
    args = ["dig", f"@{server}", "-p", str(port), zone, "AXFR", "+tcp",
            f"+time={timeout}"]
    t0 = time.monotonic()
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout + 10)
    dt = time.monotonic() - t0
    lines = [ln for ln in p.stdout.splitlines()
             if ln and not ln.startswith(";")]
    return (dt, len(lines), len(p.stdout.encode()))


def ixfr(zone: str, server: str, port: int, from_serial: int,
         timeout: int = 60) -> tuple[float, int, int]:
    """Incremental transfer from `from_serial`. Return (secs, lines, bytes)."""
    args = ["dig", f"@{server}", "-p", str(port), zone, "IXFR=" + str(from_serial),
            "+tcp", f"+time={timeout}"]
    t0 = time.monotonic()
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout + 10)
    dt = time.monotonic() - t0
    lines = [ln for ln in p.stdout.splitlines()
             if ln and not ln.startswith(";")]
    return (dt, len(lines), len(p.stdout.encode()))


def poll_until_visible(name: str, rtype: str, expected: str, server: str, port: int,
                       interval_ms: int = 50, timeout_secs: int = 30) -> float | None:
    """Poll until `name`/`rtype` resolves to `expected`. Return seconds, or None."""
    deadline = time.monotonic() + timeout_secs
    t0 = time.monotonic()
    while time.monotonic() < deadline:
        ok, _, out = dig(name, rtype, server, port)
        if ok and (expected in out):
            return time.monotonic() - t0
        time.sleep(interval_ms / 1000.0)
    return None
