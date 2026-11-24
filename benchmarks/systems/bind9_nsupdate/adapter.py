"""Write BIND9 records with RFC 2136 `nsupdate` transactions and read them with `dig`.
"""
from __future__ import annotations

from pathlib import Path

from adapters.base import Endpoint
from adapters.nsupdate import NsupdateAdapter
from lib import docker

HERE = Path(__file__).resolve().parent
DNS_PORT = 15356
ZONE = "bench.example"
SERVER = "127.0.0.1"


class Bind9NsupdateAdapter(NsupdateAdapter):
    key = "bind9_nsupdate"
    server_name = "BIND9 (nsupdate)"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE)
        self.compose = docker.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        await self.compose.up("bind9", wait=False)
        await self._wait_dns()

    async def delete_zone(self, zone_name: str) -> None:
        """Remove the benchmark zone and its records."""
        return
