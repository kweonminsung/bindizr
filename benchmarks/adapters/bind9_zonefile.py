"""Shared BIND9 record operations using zone files and rndc reload."""
from __future__ import annotations

import asyncio

from .base import DnsAdapter, Endpoint
from lib import zonefile


class Bind9ZoneFileAdapter(DnsAdapter):
    """Store records, write the primary's zone file, and reload it through RNDC."""

    def __init__(self, cfg: dict, project: str, endpoint: Endpoint, zone: str,
                 zone_path: str):
        """Initialize the primary endpoint, zone file, and record state."""
        super().__init__(cfg, project)
        self._endpoint = endpoint
        self._zone = zone
        self._zone_path = zone_path
        self.records: dict[str, dict] = {}
        self.serial = 2
        self.cid: str | None = None

    async def _run(self, *cmd: str, input: bytes | None = None) -> bool:
        """Run a container command with optional input and report its exit status."""
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.communicate(input)
        return proc.returncode == 0

    async def _flush_and_reload(self) -> bool:
        """Write the current zone file and request a server reload."""
        self.serial += 1
        text = zonefile.build_zone_file(self._zone, self.serial, self.records.values())
        # Write inside the container so BIND sees each file modification time.
        ok = await self._run("docker", "exec", "-i", self.cid, "tee", self._zone_path,
                             input=text.encode())
        if not ok:
            return False
        return await self._run("docker", "exec", self.cid, "rndc", "reload", self._zone)

    async def create_record(self, zone: str, rec: dict) -> str:
        """Create a record and return its name-and-type handle."""
        handle = f'{rec["name"]}|{rec["type"]}'
        self.records[handle] = rec
        await self._flush_and_reload()
        return handle

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Write the supplied records in one zone-file rewrite and reload."""
        for rec in records:
            self.records[f'{rec["name"]}|{rec["type"]}'] = rec
        await self._flush_and_reload()

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        name, rtype = handle.rsplit("|", 1)
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
            f"{name}.{self._zone}", rtype, "+short", "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        return bool(out.decode().strip())

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        """Merge the supplied record fields and reload the zone file."""
        self.records[handle] = {**self.records.get(handle, {}), **rec}
        return await self._flush_and_reload()

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle and reload the zone file."""
        self.records.pop(handle, None)
        return await self._flush_and_reload()

    def dns_endpoint(self) -> Endpoint:
        """Return the primary endpoint serving the managed zone."""
        return Endpoint(self._endpoint.host, self._endpoint.port)
