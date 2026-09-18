"""BIND9 + rndc adapter — manage records by rewriting the zone file and running
`rndc reload`.

This adapter participates in bulk import (B2): writing the whole zone once and
reloading once avoids a full file rewrite per record.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15357
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


def _rdata(rec: dict) -> str:
    """Render a benchmark record as zone-file record data."""
    t, v = rec["type"], rec["value"]
    if t == "MX":
        return f'{rec.get("priority", 10)} {v if v.endswith(".") else v + "."}'
    if t == "TXT":
        return f'"{v}"'
    if t == "CNAME":
        return v if v.endswith(".") else v + "."
    return v


class Bind9RndcAdapter(DnsAdapter):
    key = "bind9_rndc"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, cfg: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(cfg, project)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)
        self.records: dict[str, dict] = {}
        self.serial = 2
        self.cid: str | None = None

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("bind9", wait=False)
        self.cid = self.compose.resolve_container_id("bind9")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        """Wait until the system answers DNS queries."""
        for _ in range(timeout * 2):
            proc = await asyncio.create_subprocess_exec(
                "dig", f"@{SERVER}", "-p", str(DNS_PORT), ZONE, "SOA", "+short",
                "+tries=1", "+time=3",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
            if out.decode().strip():
                return
            await asyncio.sleep(0.5)
        raise RuntimeError("BIND9 (rndc) did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    def _zone_text(self) -> str:
        """Render the current zone records as a complete zone file."""
        lines = [
            "$TTL 3600",
            f"@ IN SOA ns1.{ZONE}. admin.{ZONE}. ( {self.serial} 3600 600 604800 3600 )",
            f"@ IN NS ns1.{ZONE}.",
            "ns1 IN A 127.0.0.1",
        ]
        for rec in self.records.values():
            lines.append(f'{rec["name"]} {rec.get("ttl", 3600)} IN {rec["type"]} {_rdata(rec)}')
        return "\n".join(lines) + "\n"

    async def _run(self, *cmd: str) -> bool:
        """Run a control command in the benchmark system container."""
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.communicate()
        return proc.returncode == 0

    async def _flush_and_reload(self) -> bool:
        """Write the current zone file and request a server reload."""
        import os

        self.serial += 1
        with tempfile.NamedTemporaryFile("w", suffix=".zone", delete=False) as fh:
            fh.write(self._zone_text())
            tmp = fh.name
        # Make world-readable so BIND (uid 53) can read the root-owned copy.
        os.chmod(tmp, 0o644)
        ok = await self._run("docker", "cp", tmp, f"{self.cid}:{ZONE_PATH}")
        Path(tmp).unlink(missing_ok=True)
        if not ok:
            return False
        return await self._run("docker", "exec", self.cid, "rndc", "reload", ZONE)

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return

    async def delete_zone(self, zone: str) -> None:
        """Remove the benchmark zone and its records."""
        self.records.clear()
        await self._flush_and_reload()

    async def create_record(self, zone: str, rec: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        handle = f'{rec["name"]}|{rec["type"]}'
        self.records[handle] = rec
        await self._flush_and_reload()
        return handle

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Import a batch of records into the benchmark zone."""
        for rec in records:
            self.records[f'{rec["name"]}|{rec["type"]}'] = rec
        await self._flush_and_reload()

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        name, rtype = handle.rsplit("|", 1)
        fqdn = f"{name}.{ZONE}"
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{SERVER}", "-p", str(DNS_PORT), fqdn, rtype, "+short",
            "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        return bool(out.decode().strip())

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        self.records[handle] = {**self.records.get(handle, {}), **rec}
        return await self._flush_and_reload()

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        self.records.pop(handle, None)
        return await self._flush_and_reload()

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint(SERVER, DNS_PORT)
