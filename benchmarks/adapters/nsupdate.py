"""Shared record operations for primaries managed through nsupdate."""
from __future__ import annotations

import asyncio

from .base import DnsAdapter, Endpoint
from lib import process, zonefile


class NsupdateAdapter(DnsAdapter):
    """Query records with dig and apply changes with nsupdate."""

    def __init__(self, config: dict, project: str, endpoint: Endpoint, zone_name: str):
        """Store the primary endpoint, managed zone, and update failure detail."""
        super().__init__(config, project)
        self._endpoint = endpoint
        self._zone_name = zone_name
        self._last_error = ""

    async def _dig(self, name: str, record_type: str) -> tuple[bool, str]:
        """Query a record through the primary's DNS endpoint."""
        proc = await process.run(
            "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
            name, record_type, "+short", "+tries=1", "+time=3",
            timeout=5, stderr=asyncio.subprocess.DEVNULL)

        text = proc.stdout.decode().strip()

        return (bool(text), text)

    async def _nsupdate(self, script: str, retries: int = 5) -> bool:
        """Send an UPDATE script, retaining the last failure for diagnostics."""
        header = f"server {self._endpoint.host} {self._endpoint.port}\nzone {self._zone_name}\n"
        payload = (header + script + "send\n").encode()
        delay = 0.05

        for attempt in range(retries + 1):
            proc = await process.run("nsupdate", input=payload,
                                     stdout=asyncio.subprocess.DEVNULL)

            if proc.returncode == 0:
                return True

            self._last_error = (proc.stderr or b"").decode(errors="replace").strip()

            # A primary can refuse updates while flushing its journal.
            if attempt < retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.5)

        return False

    def _fqdn(self, name: str) -> str:
        """Qualify a record owner with the managed zone."""
        return f"{name}.{self._zone_name}."

    async def create_record(self, zone_name: str, record: dict) -> str:
        """Create a record and return its name-and-type handle."""
        fqdn = self._fqdn(record["name"])

        ok = await self._nsupdate(
            f'update add {fqdn} {record.get("ttl", 3600)} '
            f'{record["type"]} {zonefile.build_record_data(record)}\n')

        if not ok:
            raise RuntimeError(f"nsupdate add failed: {self._last_error!r} "
                               f"rec={record['type']} {zonefile.build_record_data(record)}")

        return f'{fqdn}|{record["type"]}'

    async def get_record(self, zone_name: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        fqdn, record_type = handle.rsplit("|", 1)
        ok, _ = await self._dig(fqdn, record_type)
        return ok

    async def update_record(self, zone_name: str, handle: str, record: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        fqdn, record_type = handle.rsplit("|", 1)
        return await self._nsupdate(
            f"update delete {fqdn} {record_type}\n"
            f'update add {fqdn} {record.get("ttl", 3600)} {record_type} '
            f'{zonefile.build_record_data({**record, "type": record_type})}\n')

    async def delete_record(self, zone_name: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        fqdn, record_type = handle.rsplit("|", 1)
        return await self._nsupdate(f"update delete {fqdn} {record_type}\n")

    def dns_endpoint(self) -> Endpoint:
        """Return the primary endpoint serving the managed zone."""
        return Endpoint(self._endpoint.host, self._endpoint.port)
