"""Bulk-load CoreDNS zone files and await the `file` plugin's `reload 1s` poll.

No management API or RFC 2136 updates; per-record CRUD would measure polling delay.
"""
from __future__ import annotations

import asyncio
import io
import sys
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import Endpoint  # noqa: E402
from adapters.zonefile import ZoneFileAdapter  # noqa: E402
from lib import docker, process, zonefile  # noqa: E402

DNS_PORT = 15359
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/zones/bench.example.zone"


class CoreDnsAdapter(ZoneFileAdapter):
    key = "coredns"
    server_name = "CoreDNS"
    resource_services = ["coredns"]
    # The `transfer` plugin serves AXFR but CoreDNS keeps no journal, so an IXFR
    # request is answered with a full transfer.
    supports_ixfr = False

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE)
        self.compose = docker.Compose(HERE / "compose.yml", project)
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
        """Accept a candidate only after CoreDNS serves its new SOA serial."""
        self.serial += 1

        data = zonefile.build_zone_file(ZONE, self.serial, records.values()).encode("utf-8")
        with io.BytesIO() as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
                # CoreDNS needs read access and a fresh mtime for reloads.
                member = tarfile.TarInfo(Path(ZONE_PATH).name)
                member.mode = 0o644
                member.mtime = time.time()
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            payload = stream.getvalue()

        proc = await process.run(
            "docker", "cp", "-", f"{self.cid}:{Path(ZONE_PATH).parent}", input=payload,
            timeout=60, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

        if proc.returncode != 0:
            return False

        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout

        while loop.time() < deadline:
            got = await self._query_soa_serial()
            if got is not None and got >= self.serial:
                return True
            await asyncio.sleep(0.1)

        return False

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return  # the zone is declared in the Corefile
