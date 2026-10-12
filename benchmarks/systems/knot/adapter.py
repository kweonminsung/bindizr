"""Knot primary adapter using `nsupdate`, comparable with the BIND9+nsupdate adapter.

Bulk loads batch records into one UPDATE transaction. Knot's journal supports
IXFR deltas as well as AXFR, so it participates in every benchmark.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import Endpoint  # noqa: E402
from adapters.nsupdate import NsupdateAdapter  # noqa: E402
from lib import dockerutil, zonefile  # noqa: E402

DNS_PORT = 15360
ZONE = "bench.example"
SERVER = "127.0.0.1"


class KnotAdapter(NsupdateAdapter):
    key = "knot"
    resource_services = ["knot"]
    supports_ixfr = True
    # Updates per UPDATE transaction. A DNS message is capped at 64 KB over TCP,
    # so keep the batch well under that while still amortizing the round trip.
    update_batch = 500

    def __init__(self, cfg: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(cfg, project, Endpoint(SERVER, DNS_PORT), ZONE)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)
        self.cid: str | None = None

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("knot", wait=False)
        self.cid = self.compose.resolve_container_id("knot")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 90) -> None:
        """Wait for SOA queries and dynamic updates before prepopulating the zone."""
        for _ in range(timeout * 2):
            code, _out = await self._dig(ZONE, "SOA")
            if code:
                probe = await self._nsupdate(
                    "update add probe0.bench.example. 10 A 127.0.0.1\n"
                    "update delete probe0.bench.example. A\n")
                if probe:
                    return
            await asyncio.sleep(0.5)
        raise RuntimeError("Knot DNS did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    async def _knotc(self, *args: str) -> bool:
        """Run a Knot control command in the benchmark container."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.cid, "knotc", *args,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode != 0:
            self._last_err = (err or b"").decode(errors="replace").strip()
        return proc.returncode == 0

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return  # the zone is declared in knot.conf

    async def delete_zone(self, zone: str) -> None:
        """Purge zone contents and reload the seed file; DDNS cannot remove the configured zone.

        Omit `+zonefile`: `zonefile-sync: -1` preserves the seed for restoring the apex."""
        if not self.cid:
            return
        await self._knotc("-f", "zone-purge", "+expire", "+journal", "+timers", ZONE)
        await self._knotc("zone-reload", ZONE)
        await self._wait_dns()

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Batch adds into as few UPDATE transactions as the message size allows."""
        self.bulk_errors = 0
        for start in range(0, len(records), self.update_batch):
            chunk = records[start:start + self.update_batch]
            script = "".join(
                f'update add {self._fqdn(r["name"])} {r.get("ttl", 3600)} '
                f'{r["type"]} {zonefile.build_record_data(r)}\n'
                for r in chunk
            )
            if not await self._nsupdate(script):
                self.bulk_errors += len(chunk)
