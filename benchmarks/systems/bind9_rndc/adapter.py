"""Write BIND9 zone files and run `rndc reload`.

Benchmark 2 writes and reloads the whole zone once, avoiding per-record file rewrites.
"""
from __future__ import annotations

from pathlib import Path

from adapters.base import Endpoint
from adapters.bind9_zonefile import Bind9ZoneFileAdapter
from lib import docker

HERE = Path(__file__).resolve().parent
DNS_PORT = 15357
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


class Bind9RndcAdapter(Bind9ZoneFileAdapter):
    key = "bind9_rndc"
    server_name = "BIND9 (rndc)"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE, ZONE_PATH)
        self.compose = docker.Compose(HERE / "compose.yml", project)
