"""Bulk-load CoreDNS zone files and await the `file` plugin's `reload 1s` poll.

No management API or RFC 2136 updates; per-record CRUD would measure polling delay.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import docker, process, zonefile  # noqa: E402

DNS_PORT = 15359
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/zones/bench.example.zone"


class CoreDnsAdapter(DnsAdapter):
    key = "coredns"
    resource_services = ["coredns"]
    # The `transfer` plugin serves AXFR but CoreDNS keeps no journal, so an IXFR
    # request is answered with a full transfer.
    supports_ixfr = False

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project)
        self.compose = docker.Compose(HERE / "compose.yml", project)
        # Last snapshot confirmed by its served SOA serial.
        self.records: dict[str, dict] = {}
        self._write_lock = asyncio.Lock()
        self.serial = 1
        self.cid: str | None = None

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()
        self.compose.up("coredns", wait=False)
        self.cid = self.compose.resolve_container_id("coredns")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        """Wait until the system answers DNS queries."""
        for _ in range(timeout * 2):
            if await self._query_soa_serial() is not None:
                return
            await asyncio.sleep(0.5)
        raise RuntimeError("CoreDNS did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    async def _dig(self, name: str, rtype: str) -> str:
        """Query a record through the system DNS endpoint."""
        proc = await process.run(
            "dig", f"@{SERVER}", "-p", str(DNS_PORT), name, rtype, "+short",
            "+tries=1", "+time=3",
            timeout=5, stderr=asyncio.subprocess.DEVNULL)
        return proc.stdout.decode().strip()

    async def _query_soa_serial(self) -> int | None:
        """Query the current zone serial from the zone's SOA."""
        out = await self._dig(ZONE, "SOA")

        parts = out.split()

        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                return None

        return None

    async def _flush_and_reload(self, records: dict[str, dict], timeout: float = 30.0) -> bool:
        """Publish a candidate locally after CoreDNS serves its new SOA serial."""
        self.serial += 1

        with tempfile.NamedTemporaryFile("w", suffix=".zone", delete=False) as fh:
            fh.write(zonefile.build_zone_file(ZONE, self.serial, records.values()))
            tmp = fh.name

        try:
            os.chmod(tmp, 0o644)  # docker cp preserves perms; CoreDNS must be able to read it
            proc = await process.run(
                "docker", "cp", tmp, f"{self.cid}:{ZONE_PATH}", timeout=60,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        finally:
            Path(tmp).unlink(missing_ok=True)

        if proc.returncode != 0:
            return False

        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout

        while loop.time() < deadline:
            got = await self._query_soa_serial()
            if got is not None and got >= self.serial:
                self.records = records
                return True
            await asyncio.sleep(0.1)

        return False

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return  # the zone is declared in the Corefile

    async def delete_zone(self, zone: str) -> None:
        """Clear the zone's records and reload its zone file."""

        # Rewrite the file so CoreDNS stops serving the previous records.
        async with self._write_lock:
            if not await self._flush_and_reload({}):
                raise RuntimeError("clearing the CoreDNS zone failed")

    async def import_records(self, zone: str, records: list[dict]) -> None:
        """Write the whole set in one rewrite so the reload cost is paid once."""
        async with self._write_lock:
            self.bulk_errors = 0
            candidate = dict(self.records)
            for record in records:
                candidate[f'{record["name"]}|{record["type"]}'] = record
            if not await self._flush_and_reload(candidate):
                self.bulk_errors = len(records)

    async def create_record(self, zone: str, record: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        handle = f'{record["name"]}|{record["type"]}'
        async with self._write_lock:
            if not await self._flush_and_reload({**self.records, handle: record}):
                raise RuntimeError(f"creating CoreDNS record {handle} failed")
        return handle

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        name, rtype = handle.rsplit("|", 1)
        return bool(await self._dig(f"{name}.{ZONE}", rtype))

    async def update_record(self, zone: str, handle: str, record: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        async with self._write_lock:
            candidate = {**self.records, handle: {**self.records.get(handle, {}), **record}}
            return await self._flush_and_reload(candidate)

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        async with self._write_lock:
            candidate = dict(self.records)
            candidate.pop(handle, None)
            return await self._flush_and_reload(candidate)

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint(SERVER, DNS_PORT)
