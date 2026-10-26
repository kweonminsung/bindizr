"""Own file-backed record snapshots while concrete adapters own publication readiness."""
from __future__ import annotations

import abc
import asyncio

from .base import DnsAdapter, Endpoint
from lib import process


class ZoneFileAdapter(DnsAdapter):
    """Serialize candidate mutations and retain only successfully published snapshots."""

    server_name: str

    def __init__(self, config: dict, project: str, endpoint: Endpoint, zone: str):
        """Store the managed zone, its endpoint, and the last published record set."""
        super().__init__(config, project)
        self._endpoint = endpoint
        self._zone = zone
        self.records: dict[str, dict] = {}
        self._write_lock = asyncio.Lock()
        self.serial = 1

    @abc.abstractmethod
    async def _flush_and_reload(self, records: dict[str, dict]) -> bool:
        """Publish a candidate using this server's completion guarantee."""

    async def _publish(self, records: dict[str, dict]) -> bool:
        """Advance the local snapshot only after the concrete publisher accepts it."""
        if not await self._flush_and_reload(records):
            return False
        self.records = records
        return True

    async def delete_zone(self, zone: str) -> None:
        """Clear the configured zone before the next workload."""
        async with self._write_lock:
            if not await self._publish({}):
                raise RuntimeError(f"clearing the {self.server_name} zone failed")

    async def create_record(self, zone: str, record: dict) -> str:
        """Publish a record and return its name-and-type handle on success."""
        handle = f'{record["name"]}|{record["type"]}'
        async with self._write_lock:
            if not await self._publish({**self.records, handle: record}):
                raise RuntimeError(f"creating {self.server_name} record {handle} failed")
        return handle

    async def import_records(self, zone: str, records: list[dict]) -> None:
        """Publish a merged batch and count records rejected by the publisher."""
        async with self._write_lock:
            self.bulk_errors = 0
            candidate = dict(self.records)
            for record in records:
                candidate[f'{record["name"]}|{record["type"]}'] = record
            if not await self._publish(candidate):
                self.bulk_errors = len(records)

    async def get_record(self, zone: str, handle: str) -> bool:
        """Query the record through the configured server endpoint."""
        name, rtype = handle.rsplit("|", 1)
        reply = await process.run(
            "dig", f"@{self._endpoint.host}", "-p", str(self._endpoint.port),
            f"{name}.{self._zone}", rtype, "+short", "+tries=1", "+time=3",
            timeout=5, stderr=asyncio.subprocess.DEVNULL)
        return bool(reply.stdout.decode().strip())

    async def update_record(self, zone: str, handle: str, record: dict) -> bool:
        """Publish the existing snapshot with this record's supplied fields merged."""
        async with self._write_lock:
            candidate = {**self.records, handle: {**self.records.get(handle, {}), **record}}
            return await self._publish(candidate)

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Publish the existing snapshot without this record."""
        async with self._write_lock:
            candidate = dict(self.records)
            candidate.pop(handle, None)
            return await self._publish(candidate)

    def dns_endpoint(self) -> Endpoint:
        """Return the endpoint serving the managed zone."""
        return Endpoint(self._endpoint.host, self._endpoint.port)
