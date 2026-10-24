"""Measure query latency, AXFR and propagation with host `dig` against address:port.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import time

from . import process


# dig prints this only after its AXFR/IXFR state machine reaches completion.
XFR_SIZE = re.compile(r"^;; XFR size: (\d+) records \(messages \d+, bytes \d+\)\s*$", re.MULTILINE)
RESPONSE_STATUS = re.compile(r"^;; ->>HEADER<<- .*status: ([A-Z0-9]+),", re.MULTILINE)


class TransferError(RuntimeError):
    """A failed or incomplete dig transfer, retaining its response status if any."""

    def __init__(self, zone: str, server: str, port: int, qtype: str,
                 detail: str, rcode: str | None = None):
        """Name the failed exchange and preserve its protocol classification."""
        super().__init__(f"{qtype} of {zone} from {server}:{port} failed: {detail}")
        self.rcode = rcode


async def query(name: str, rtype: str, server: str, port: int,
                timeout: int = 5) -> tuple[bool, float, str]:
    """Return (answered, latency_secs, raw_output)."""
    args = ["dig", f"@{server}", "-p", str(port), name, rtype, "+tries=1",
            f"+time={timeout}", "+short"]
    t0 = time.monotonic()

    try:
        p = await process.run(*args, timeout=timeout + 2)
        dt = time.monotonic() - t0
        out = p.stdout.decode().strip()
        return (p.returncode == 0 and bool(out), dt, out)
    except subprocess.TimeoutExpired:
        return (False, time.monotonic() - t0, "")


async def _transfer(zone: str, server: str, port: int, qtype: str,
                    timeout: int) -> tuple[float, int, int]:
    """Measure only completed transfers, leaving SOA-only/delta/fallback validation to dig."""
    args = ["dig", f"@{server}", "-p", str(port), zone, qtype, "+tcp",
            f"+time={timeout}", "+tries=1", "+noall", "+noshort", "+answer",
            "+comments", "+stats", "+noonesoa", "+nomultiline", "+ttlid", "+cl"]
    t0 = time.monotonic()
    try:
        p = await process.run(*args, timeout=timeout + 10)
    except subprocess.TimeoutExpired as error:
        raise TransferError(zone, server, port, qtype, "timed out") from error
    dt = time.monotonic() - t0
    out = p.stdout.decode()
    lines = [line for line in out.splitlines() if line and not line.startswith(";")]
    completions = XFR_SIZE.findall(out)
    statuses = RESPONSE_STATUS.findall(out)
    rcode = next((status for status in statuses if status != "NOERROR"), None)

    # Some dig versions exit zero after an early EOF or a refused transfer.
    if (p.returncode != 0 or rcode is not None or len(completions) != 1
            or int(completions[0]) != len(lines) or not lines):
        detail = p.stderr.decode().strip() or rcode or "incomplete transfer"
        raise TransferError(zone, server, port, qtype, detail, rcode)

    first = lines[0].split()
    last = lines[-1].split()
    if (len(first) != 11 or first[2:4] != ["IN", "SOA"]
            or (len(lines) == 1 and qtype == "AXFR")
            or (len(lines) > 1 and [field.lower() for field in first]
                != [field.lower() for field in last])):
        raise TransferError(zone, server, port, qtype, "invalid SOA boundaries")

    return (dt, len(lines), len(p.stdout))


async def axfr(zone: str, server: str, port: int, timeout: int = 300) -> tuple[float, int, int]:
    """Run an AXFR and report its duration, record count, and output size."""
    return await _transfer(zone, server, port, "AXFR", timeout)


async def ixfr(zone: str, server: str, port: int, from_serial: int,
               timeout: int = 60) -> tuple[float, int, int]:
    """Run an IXFR from a serial and report its duration and transfer size."""
    return await _transfer(zone, server, port, f"IXFR={from_serial}", timeout)


async def count_axfr_records(zone: str, server: str, port: int,
                             timeout: int = 300) -> int | None:
    """Probe a complete AXFR's size, or report unavailable for a polling caller."""
    try:
        return (await axfr(zone, server, port, timeout))[1]
    except TransferError:
        return None


async def zone_is_cleared(zone: str, server: str, port: int,
                          apex_lines: int, timeout: int = 5) -> bool:
    """Accept a complete apex-only zone or an explicit unserved SOA response, never silence."""
    try:
        return (await axfr(zone, server, port, timeout))[1] <= apex_lines
    except TransferError as error:
        if error.rcode in ("NXDOMAIN", "NOTAUTH"):
            return True

    # An AXFR refusal alone says nothing about the old zone's presence.
    args = ["dig", f"@{server}", "-p", str(port), zone, "SOA", "+norecurse",
            "+tries=1", f"+time={timeout}", "+noall", "+noshort", "+comments"]
    try:
        reply = await process.run(*args, timeout=timeout + 2)
    except subprocess.TimeoutExpired:
        return False
    statuses = RESPONSE_STATUS.findall(reply.stdout.decode())
    return reply.returncode == 0 and statuses in (["NXDOMAIN"], ["NOTAUTH"], ["REFUSED"])


async def poll_until_visible(name: str, rtype: str, expected: str, server: str, port: int,
                             interval_ms: int = 50, timeout_secs: int = 30) -> float | None:
    """Poll until `name`/`rtype` resolves to `expected`. Return seconds, or None."""
    deadline = time.monotonic() + timeout_secs
    t0 = time.monotonic()

    while time.monotonic() < deadline:
        ok, _, out = await query(name, rtype, server, port)
        # Whole-line match: `in out` would accept 10.0.0.1 for an answer of
        # 10.0.0.10 and report propagation that never happened.
        if ok and expected in out.splitlines():
            return time.monotonic() - t0
        await asyncio.sleep(interval_ms / 1000.0)

    return None


async def first_unqueryable(records: list[dict], zone: str, server: str, port: int,
                            interval_ms: int = 50,
                            timeout_secs: int = 30) -> dict | None:
    """Return the first unavailable record sampled across the zone, or None.
    Check first, middle and last because bulk writes may still be propagating."""
    suffix = zone.rstrip(".")

    for idx in sorted({0, len(records) // 2, len(records) - 1}) if records else []:
        record = records[idx]
        if await poll_until_visible(f'{record["name"]}.{suffix}', record["type"], record["value"],
                                    server, port, interval_ms, timeout_secs) is None:
            return record

    return None
