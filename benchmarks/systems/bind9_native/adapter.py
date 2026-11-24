"""Provide the standalone BIND9 primary baseline for Benchmark 8 QPS comparisons.

Bulk-load a zone file and reload as in the rndc adapter; per-record CRUD is secondary.
"""
from __future__ import annotations

from pathlib import Path

from adapters.base import Endpoint
from adapters.bind9_zonefile import Bind9ZoneFileAdapter
from lib import docker

HERE = Path(__file__).resolve().parent
DNS_PORT = 15358
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


class Bind9NativeAdapter(Bind9ZoneFileAdapter):
    key = "bind9_native"
    server_name = "Native BIND9"
    resource_services = ["bind9"]

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project, Endpoint(SERVER, DNS_PORT), ZONE, ZONE_PATH)
        self.compose = docker.Compose(HERE / "compose.yml", project)
