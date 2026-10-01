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


def _transfer(zone: str, server: str, port: int, qtype: str,
              timeout: int) -> tuple[float, int, int]:
    """Return transfer duration, answer-line count, and bytes.

    The count includes both framing SOAs; an empty zone still has apex records."""
    args = ["dig", f"@{server}", "-p", str(port), zone, qtype, "+tcp",
            f"+time={timeout}"]
    t0 = time.monotonic()
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout + 10)
    dt = time.monotonic() - t0
    lines = [ln for ln in p.stdout.splitlines() if ln and not ln.startswith(";")]
    return (dt, len(lines), len(p.stdout.encode()))


def axfr(zone: str, server: str, port: int, timeout: int = 300) -> tuple[float, int, int]:
    """Run an AXFR and report its duration, record count, and output size."""
    return _transfer(zone, server, port, "AXFR", timeout)


def ixfr(zone: str, server: str, port: int, from_serial: int,
         timeout: int = 60) -> tuple[float, int, int]:
    """Run an IXFR from a serial and report its duration and transfer size."""
    return _transfer(zone, server, port, f"IXFR={from_serial}", timeout)


def poll_until_visible(name: str, rtype: str, expected: str, server: str, port: int,
                       interval_ms: int = 50, timeout_secs: int = 30) -> float | None:
    """Poll until `name`/`rtype` resolves to `expected`. Return seconds, or None."""
    deadline = time.monotonic() + timeout_secs
    t0 = time.monotonic()
    while time.monotonic() < deadline:
        ok, _, out = dig(name, rtype, server, port)
        # Whole-line match: `in out` would accept 10.0.0.1 for an answer of
        # 10.0.0.10 and report propagation that never happened.
        if ok and expected in out.splitlines():
            return time.monotonic() - t0
        time.sleep(interval_ms / 1000.0)
    return None


def first_unqueryable(records: list[dict], zone: str, server: str, port: int,
                      interval_ms: int = 50,
                      timeout_secs: int = 30) -> dict | None:
    """Return the first unavailable record among the first, middle, and last, or None.

    Sample across the zone because a bulk write may still be propagating."""
    suffix = zone.rstrip(".")
    for idx in sorted({0, len(records) // 2, len(records) - 1}) if records else []:
        rec = records[idx]
        if poll_until_visible(f'{rec["name"]}.{suffix}', rec["type"], rec["value"],
                              server, port, interval_ms, timeout_secs) is None:
            return rec
    return None
