"""Knot primary adapter using `nsupdate`, comparable with the BIND9+nsupdate adapter.

Bulk loads batch records into one UPDATE transaction. Knot's journal supports
IXFR deltas as well as AXFR, so it participates in every benchmark.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from adapters.base import Endpoint
from adapters.nsupdate import NsupdateAdapter
from lib import docker, process, zonefile

HERE = Path(__file__).resolve().parent
DNS_PORT = 15360
ZONE = "bench.example"
SERVER = "127.0.0.1"


class KnotAdapter(NsupdateAdapter):
    key = "knot"
    server_name = "Knot DNS"
    resource_services = ["knot"]
    supports_ixfr = True
    # Updates per UPDATE transaction. A DNS message is capped at 64 KB over TCP,
    # so keep the batch well under that while still amortizing the round trip.
    update_batch = 500

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE)
        self.compose = docker.Compose(HERE / "compose.yml", project)
        self.container_id: str | None = None

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        await self.compose.up("knot", wait=False)
        self.container_id = self.compose.resolve_container_id("knot")
        await self._wait_dns()

    async def _knotc(self, *args: str) -> bool:
        """Run a Knot control command in the benchmark container."""
        result = await process.run(
            "docker", "exec", self.container_id, "knotc", *args,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)

        if result.returncode != 0:
            self._last_error = (result.stderr or b"").decode(errors="replace").strip()

        return result.returncode == 0

    async def delete_zone(self, zone_name: str) -> None:
        """Purge zone contents and reload the seed file; DDNS cannot remove the configured zone.

        Omit `+zonefile`: `zonefile-sync: -1` preserves the seed for restoring the apex."""
        if not self.container_id:
            return

        await self._knotc("-f", "zone-purge", "+expire", "+journal", "+timers", ZONE)
        await self._knotc("zone-reload", ZONE)
        await self._wait_dns()

    async def import_records(self, zone_name: str, records: list[dict]) -> None:
        """Batch adds into as few UPDATE transactions as the message size allows."""
        self.bulk_errors = 0

        for start in range(0, len(records), self.update_batch):
            chunk = records[start:start + self.update_batch]
            script = "".join(
                f'update add {self._fqdn(record["name"])} {record.get("ttl", 3600)} '
                f'{record["type"]} {zonefile.build_record_data(record)}\n'
                for record in chunk
            )

            if not await self._nsupdate(script):
                self.bulk_errors += len(chunk)
