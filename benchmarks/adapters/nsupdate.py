"""Shared record operations for primaries managed through nsupdate."""
from __future__ import annotations

import asyncio

from .base import DnsAdapter, Endpoint
from lib import zonefile


class NsupdateAdapter(DnsAdapter):
    """Query records with dig and apply changes with nsupdate."""

    def __init__(self, cfg: dict, project: str, endpoint: Endpoint, zone: str):
        """Store the primary endpoint, managed zone, and update failure detail."""
        super().__init__(cfg, project)
        self._endpoint = endpoint
        self._zone = zone
        self._last_err = ""

    async def _dig(self, name: str, rtype: str) -> tuple[bool, str]:
        """Query a record through the primary's DNS endpoint."""
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
            name, rtype, "+short", "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        text = out.decode().strip()
        return (bool(text), text)

    async def _nsupdate(self, script: str, retries: int = 5) -> bool:
        """Send an UPDATE script, retaining the last failure for diagnostics."""
        header = f"server {self._endpoint.host} {self._endpoint.port}\nzone {self._zone}\n"
        payload = (header + script + "send\n").encode()
        delay = 0.05
        for attempt in range(retries + 1):
            proc = await asyncio.create_subprocess_exec(
                "nsupdate", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate(payload)
            if proc.returncode == 0:
                return True
            self._last_err = (err or b"").decode(errors="replace").strip()
            # A primary can refuse updates while flushing its journal.
            if attempt < retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.5)
        return False

    def _fqdn(self, name: str) -> str:
        """Qualify a record owner with the managed zone."""
        return f"{name}.{self._zone}."

    async def create_record(self, zone: str, rec: dict) -> str:
        """Create a record and return its name-and-type handle."""
        fqdn = self._fqdn(rec["name"])
        ok = await self._nsupdate(
            f'update add {fqdn} {rec.get("ttl", 3600)} '
            f'{rec["type"]} {zonefile.build_record_data(rec)}\n')
        if not ok:
            raise RuntimeError(f"nsupdate add failed: {self._last_err!r} "
                               f"rec={rec['type']} {zonefile.build_record_data(rec)}")
        return f'{fqdn}|{rec["type"]}'

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        fqdn, rtype = handle.rsplit("|", 1)
        ok, _ = await self._dig(fqdn, rtype)
        return ok

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        fqdn, rtype = handle.rsplit("|", 1)
        return await self._nsupdate(
            f"update delete {fqdn} {rtype}\n"
            f'update add {fqdn} {rec.get("ttl", 3600)} {rtype} '
            f'{zonefile.build_record_data({**rec, "type": rtype})}\n')

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        fqdn, rtype = handle.rsplit("|", 1)
        return await self._nsupdate(f"update delete {fqdn} {rtype}\n")

    def dns_endpoint(self) -> Endpoint:
        """Return the primary endpoint serving the managed zone."""
        return Endpoint(self._endpoint.host, self._endpoint.port)
