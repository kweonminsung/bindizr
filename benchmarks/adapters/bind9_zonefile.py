"""Shared BIND9 record operations using zone files and rndc reload."""
from __future__ import annotations

import asyncio

from .base import DnsAdapter, Endpoint
from lib import process, zonefile


class Bind9ZoneFileAdapter(DnsAdapter):
    """Store records, write the primary's zone file, and reload it through RNDC."""

    def __init__(self, config: dict, project: str, endpoint: Endpoint, zone: str,
                 zone_path: str):
        """Initialize the primary endpoint, zone file, and record state."""
        super().__init__(config, project)
        self._endpoint = endpoint
        self._zone = zone
        self._zone_path = zone_path
        # Last successful file write and reload command; failed I/O may leave
        # server state uncertain until the next complete rewrite.
        self.records: dict[str, dict] = {}
        self._write_lock = asyncio.Lock()
        self.serial = 2
        self.cid: str | None = None

    async def _run(self, *cmd: str, input: bytes | None = None) -> bool:
        """Run a container command with optional input and report its exit status."""
        proc = await process.run(*cmd, input=input, timeout=60,
                                 stdout=asyncio.subprocess.DEVNULL,
                                 stderr=asyncio.subprocess.DEVNULL)
        return proc.returncode == 0

    async def _flush_and_reload(self, records: dict[str, dict]) -> bool:
        """Write a candidate snapshot and publish it locally only after reload succeeds."""
        self.serial += 1
        text = zonefile.build_zone_file(self._zone, self.serial, records.values())

        # Write inside the container so BIND sees each file modification time.
        ok = await self._run("docker", "exec", "-i", self.cid, "tee", self._zone_path,
                             input=text.encode())

        if not ok:
            return False

        if not await self._run("docker", "exec", self.cid, "rndc", "reload", self._zone):
            return False
        self.records = records
        return True

    async def delete_zone(self, zone: str) -> None:
        """Restore the configured zone's apex before the next workload."""
        async with self._write_lock:
            if not await self._flush_and_reload({}):
                raise RuntimeError("clearing the BIND9 zone failed")

    async def create_record(self, zone: str, record: dict) -> str:
        """Create a record and return its name-and-type handle."""
        handle = f'{record["name"]}|{record["type"]}'
        async with self._write_lock:
            if not await self._flush_and_reload({**self.records, handle: record}):
                raise RuntimeError(f"creating BIND9 record {handle} failed")
        return handle

    async def import_records(self, zone: str, records: list[dict]) -> None:
        """Write the supplied records in one zone-file rewrite and reload."""
        async with self._write_lock:
            self.bulk_errors = 0
            candidate = dict(self.records)
            for record in records:
                candidate[f'{record["name"]}|{record["type"]}'] = record
            if not await self._flush_and_reload(candidate):
                self.bulk_errors = len(records)

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        name, rtype = handle.rsplit("|", 1)

        proc = await process.run(
            "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
            f"{name}.{self._zone}", rtype, "+short", "+tries=1", "+time=3",
            timeout=5, stderr=asyncio.subprocess.DEVNULL)

        return bool(proc.stdout.decode().strip())

    async def update_record(self, zone: str, handle: str, record: dict) -> bool:
        """Merge the supplied record fields and reload the zone file."""
        async with self._write_lock:
            candidate = {**self.records, handle: {**self.records.get(handle, {}), **record}}
            return await self._flush_and_reload(candidate)

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle and reload the zone file."""
        async with self._write_lock:
            candidate = dict(self.records)
            candidate.pop(handle, None)
            return await self._flush_and_reload(candidate)

    def dns_endpoint(self) -> Endpoint:
        """Return the primary endpoint serving the managed zone."""
        return Endpoint(self._endpoint.host, self._endpoint.port)
