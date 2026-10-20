"""Write BIND9 records with RFC 2136 `nsupdate` transactions and read them with `dig`.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import Endpoint  # noqa: E402
from adapters.nsupdate import NsupdateAdapter  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15356
ZONE = "bench.example"
SERVER = "127.0.0.1"


class Bind9NsupdateAdapter(NsupdateAdapter):
    key = "bind9_nsupdate"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, cfg: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(cfg, project, Endpoint(SERVER, DNS_PORT), ZONE)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("bind9", wait=False)
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
        raise RuntimeError("BIND9 (nsupdate) did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        self.compose.down()

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        return  # primary zone already exists

    async def delete_zone(self, zone: str) -> None:
        """Remove the benchmark zone and its records."""
        return
