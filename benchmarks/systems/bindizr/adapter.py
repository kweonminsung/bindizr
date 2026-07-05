"""Bindizr adapter — drives the HTTP control-plane API.

Key point for the benchmark story: writes go to Bindizr's API, but DNS queries
are answered by the BIND9 secondary (`dns_endpoint`), which auto-configures
zones via the catalog zone. Bindizr is never in the query path.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import aiohttp

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

API_PORT = 18000
DNS_PORT = 15353


class BindizrAdapter(DnsAdapter):
    key = "bindizr"
    resource_services = ["bindizr", "bind9"]
    supports_ixfr = True
    # Bindizr serialises writes (SOA bump + XFR); keep bulk concurrency modest so
    # SQLite/MySQL write locks don't dominate. MySQL/PG tolerate more than SQLite.
    bulk_concurrency = 8

    def __init__(self, cfg: dict, project: str, db_type: str = "sqlite",
                 notify_after_update: bool = True):
        super().__init__(cfg, project)
        self.db_type = db_type
        self.notify_after_update = notify_after_update
        self.base = f"http://localhost:{API_PORT}"
        self.session: aiohttp.ClientSession | None = None
        env = {"BINDIZR_DB_TYPE": db_type,
               "BINDIZR_NOTIFY_AFTER_UPDATE": "true" if notify_after_update else "false"}
        if db_type == "mysql":
            env["COMPOSE_PROFILES"] = "mysql"
        elif db_type == "postgresql":
            env["COMPOSE_PROFILES"] = "postgres"
        self.compose = dockerutil.Compose(HERE / "compose.yml", project, env=env)

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        services = ["bindizr", "bind9"]
        if self.db_type == "mysql":
            services = ["mysql", *services]
        elif self.db_type == "postgresql":
            services = ["postgres", *services]
        self.compose.up(*services, wait=True)
        self.session = aiohttp.ClientSession()
        await self._wait_api()

    async def _wait_api(self, timeout: int = 60) -> None:
        for _ in range(timeout * 2):
            try:
                async with self.session.get(self.base + "/", timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        return
            except Exception:
                pass
            await asyncio.sleep(0.5)
        raise RuntimeError("Bindizr API did not become ready")

    async def teardown(self) -> None:
        if self.session:
            await self.session.close()
        self.compose.down()

    async def create_zone(self, zone: str) -> None:
        z = zone.rstrip(".")
        body = {
            "name": z,
            "primary_ns": f"ns1.{z}.",
            "admin_email": f"admin@{z}",
            "ttl": 3600,
        }
        async with self.session.post(self.base + "/zones", json=body) as r:
            if r.status not in (200, 201, 409):
                raise RuntimeError(f"create_zone failed: {r.status} {await r.text()}")

    async def delete_zone(self, zone: str) -> None:
        async with self.session.delete(self.base + f"/zones/{zone.rstrip('.')}") as r:
            await r.read()

    def _record_body(self, zone: str, rec: dict) -> dict:
        body = {
            "name": rec["name"],
            "record_type": rec["type"],
            "value": rec["value"],
            "ttl": rec.get("ttl", 3600),
            "zone_name": zone.rstrip("."),
        }
        if "priority" in rec:
            body["priority"] = rec["priority"]
        return body

    async def create_record(self, zone: str, rec: dict) -> str:
        async with self.session.post(self.base + "/records", json=self._record_body(zone, rec)) as r:
            if r.status not in (200, 201):
                raise RuntimeError(f"create_record {r.status}: {await r.text()}")
            data = await r.json()
            return str(data["record"]["id"])

    async def get_record(self, zone: str, handle: str) -> bool:
        async with self.session.get(self.base + f"/records/{handle}") as r:
            await r.read()
            return r.status == 200

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        body = {
            "name": rec["name"],
            "record_type": rec["type"],
            "value": rec["value"],
            "ttl": rec.get("ttl", 3600),
        }
        if "priority" in rec:
            body["priority"] = rec["priority"]
        async with self.session.put(self.base + f"/records/{handle}", json=body) as r:
            await r.read()
            return r.status == 200

    async def delete_record(self, zone: str, handle: str) -> bool:
        async with self.session.delete(self.base + f"/records/{handle}") as r:
            await r.read()
            return r.status == 200

    def dns_endpoint(self) -> Endpoint:
        return Endpoint("127.0.0.1", DNS_PORT)
