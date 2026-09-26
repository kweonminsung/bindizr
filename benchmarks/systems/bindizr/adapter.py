"""Bindizr adapter — drives the HTTP control-plane API.

Key point for the benchmark story: writes go to Bindizr's API, but DNS queries
are answered by the BIND9 secondary (`dns_endpoint`), which auto-configures
zones via the catalog zone. Bindizr is never in the query path.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import aiohttp

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

API_PORT = 18000
DNS_PORT = 15353

# Attempts per chunk in the bulk/import paths before it is counted as failed.
POST_ATTEMPTS = 4


class BindizrAdapter(DnsAdapter):
    key = "bindizr"
    #: Compose service that answers queries. Bindizr drives every secondary
    #: the same way, so a subclass swaps the implementation and nothing else.
    secondary_service = "bind9"
    supports_ixfr = True
    supports_zone_import = True
    # Records per request. Each chunk is one server-side transaction — a single
    # serial bump and NOTIFY — so the chunk size bounds both memory and how much
    # NOTIFY/XFR traffic a bulk load generates.
    bulk_chunk = 2000
    import_chunk = 5000

    def __init__(self, cfg: dict, project: str, db_type: str | None = None,
                 notify_after_update: bool = True,
                 notify_batch_ms: int | None = None,
                 transfer_cache: bool | None = None,
                 log_level: str | None = None):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(cfg, project)
        # b07 passes db_type; every other benchmark takes the env knob so it can
        # be pointed at any backend.
        db_type = db_type or os.environ.get("BENCH_BINDIZR_DB_TYPE", "sqlite")
        self.db_type = db_type
        # mysql/postgres run as their own containers, so b07's per-backend
        # CPU/mem columns only cover the backend if it is sampled too.
        self.resource_services = ["bindizr", self.secondary_service]
        if db_type == "mysql":
            self.resource_services.append("mysql")
        elif db_type == "postgresql":
            self.resource_services.append("postgres")
        self.notify_after_update = notify_after_update
        # None => Bindizr's own defaults (0 / true); see compose.yml.
        self.notify_batch_ms = notify_batch_ms if notify_batch_ms is not None else int(
            os.environ.get("BENCH_BINDIZR_NOTIFY_BATCH_MS", "0"))
        self.transfer_cache = transfer_cache if transfer_cache is not None else (
            os.environ.get("BENCH_BINDIZR_TRANSFER_CACHE", "true").lower() == "true")
        # Raise to "debug" to surface the server's per-stage timing lines
        # (event=record_bulk_create_timing / event=zone_import_timing).
        self.log_level = log_level or os.environ.get("BENCH_BINDIZR_LOG_LEVEL", "info")
        # Overridable so JSON-bulk and zone-import can be compared at matched
        # chunk sizes rather than at their differing defaults.
        self.bulk_chunk = int(os.environ.get("BENCH_BINDIZR_BULK_CHUNK", str(self.bulk_chunk)))
        self.import_chunk = int(os.environ.get("BENCH_BINDIZR_IMPORT_CHUNK", str(self.import_chunk)))
        self.base = f"http://localhost:{API_PORT}"
        self.session: aiohttp.ClientSession | None = None
        env = {"BINDIZR_DB_TYPE": db_type,
               "BINDIZR_NOTIFY_BATCH_MS": str(self.notify_batch_ms),
               "BINDIZR_LOG_LEVEL": self.log_level}
        # A zero record budget is how the transfer cache is turned off.
        if not self.transfer_cache:
            env["BINDIZR_TRANSFER_CACHE_MAX_RECORDS"] = "0"
        # bind9 carries no profile, so the default system starts as it always has.
        profiles = []
        if db_type == "mysql":
            profiles.append("mysql")
        elif db_type == "postgresql":
            profiles.append("postgres")
        if self.secondary_service != "bind9":
            profiles.append(self.secondary_service)
        if profiles:
            env["COMPOSE_PROFILES"] = ",".join(profiles)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project, env=env)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        # A networked backend waits on its own: bindizr exits when the DB host
        # does not resolve yet, and that exit alone fails a shared `up --wait`.
        db_service = {"mysql": "mysql", "postgresql": "postgres"}.get(self.db_type)
        if db_service:
            self.compose.up(db_service, wait=True)
        self.compose.up("bindizr", self.secondary_service, wait=True)
        self.session = aiohttp.ClientSession()
        await self._wait_api()
        # A registered secondary receives every NOTIFY, so a write-path run
        # registers none.
        if self.notify_after_update:
            await self._register_secondary()

    async def _register_secondary(self) -> None:
        """Register the secondary service so it receives NOTIFY and may transfer."""
        body = {"name": self.secondary_service, "address": f"{self.secondary_service}:53"}
        async with self.session.post(self.base + "/secondaries", json=body) as r:
            if r.status != 201:
                raise RuntimeError(f"registering the secondary failed: {r.status} {await r.text()}")

    async def _wait_api(self, timeout: int = 60) -> None:
        """Wait until the system API is ready."""
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
        """Stop the benchmark system and release its resources."""
        if self.session:
            await self.session.close()
        self.compose.down()

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark, with the NS records its secondary needs."""
        z = zone.rstrip(".")
        body = {
            "name": z,
            "mname": f"ns1.{z}.",
            "rname": f"admin@{z}",
            "default_ttl": 3600,
        }
        async with self.session.post(self.base + "/zones", json=body) as r:
            if r.status not in (200, 201, 409):
                raise RuntimeError(f"create_zone failed: {r.status} {await r.text()}")
        # Bindizr leaves NS records to the operator, and BIND9 loads no zone
        # whose apex has no NS or whose in-zone NS has no address. The other
        # systems' zone files carry these same two.
        for rec in ({"name": "@", "type": "NS", "value": f"ns1.{z}."},
                    {"name": "ns1", "type": "A", "value": "127.0.0.1"}):
            body = {**rec, "zone_name": z, "ttl": 3600}
            async with self.session.post(self.base + "/records", json=body) as r:
                if r.status not in (200, 201, 409):
                    raise RuntimeError(
                        f"create_zone {rec['type']} failed: {r.status} {await r.text()}")

    async def delete_zone(self, zone: str) -> None:
        """Remove the benchmark zone and its records."""
        async with self.session.delete(self.base + f"/zones/{zone.rstrip('.')}") as r:
            await r.read()

    def _record_body(self, zone: str, rec: dict) -> dict:
        """Build a bindizr record request from a benchmark record."""
        return {**self._bulk_item(rec), "zone_name": zone.rstrip(".")}

    async def create_record(self, zone: str, rec: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        async with self.session.post(self.base + "/records", json=self._record_body(zone, rec)) as r:
            if r.status not in (200, 201):
                raise RuntimeError(f"create_record {r.status}: {await r.text()}")
            data = await r.json()
            return str(data["record"]["id"])

    async def get_record(self, zone: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        async with self.session.get(self.base + f"/records/{handle}") as r:
            await r.read()
            return r.status == 200

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        body = self._bulk_item(rec)
        async with self.session.put(self.base + f"/records/{handle}", json=body) as r:
            await r.read()
            return r.status == 200

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        async with self.session.delete(self.base + f"/records/{handle}") as r:
            await r.read()
            return r.status == 200

    def _bulk_item(self, rec: dict) -> dict:
        """Build one record entry for the bindizr bulk API."""
        item = {
            "name": rec["name"],
            "type": rec["type"],
            "value": rec["value"],
            "ttl": rec.get("ttl", 3600),
        }
        if "priority" in rec:
            item["priority"] = rec["priority"]
        return item

    async def _post_with_retry(self, url: str, body: dict, count: int,
                               check_applied: bool = False) -> int:
        """POST `body`, retrying transient failures. Return how many records still
        failed (0 on success).

        The zone-import endpoint answers 200 with `applied=false` when validation
        rejects the chunk and nothing is inserted, so `check_applied` reads the
        body to catch that. Rejection is deterministic and not retried.
        """
        delay = 0.05
        for attempt in range(POST_ATTEMPTS):
            try:
                async with self.session.post(url, json=body) as r:
                    if r.status in (200, 201):
                        if not check_applied:
                            return 0
                        data = await r.json()
                        return 0 if data.get("applied") else count
            except Exception:
                pass
            if attempt < POST_ATTEMPTS - 1:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 1.0)
        return count

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Bulk-insert via Bindizr's `/records/bulk` API in single-transaction
        chunks (each chunk bumps the serial once and sends one NOTIFY)."""
        self.bulk_errors = 0
        url = self.base + "/records/bulk"
        for start in range(0, len(records), self.bulk_chunk):
            chunk = records[start:start + self.bulk_chunk]
            body = {"zone_name": zone.rstrip("."),
                    "records": [self._bulk_item(r) for r in chunk]}
            self.bulk_errors += await self._post_with_retry(url, body, len(chunk))

    def _zone_line(self, rec: dict) -> str:
        """Render a benchmark record as a zone-file line."""
        ttl = rec.get("ttl", 3600)
        rdata = rec["value"]
        if rec["type"] == "TXT":
            rdata = '"{}"'.format(rec["value"].replace("\\", "\\\\").replace('"', '\\"'))
        elif rec["type"] == "MX":
            rdata = f'{rec.get("priority", 10)} {rec["value"]}'
        return f'{rec["name"]} {ttl} IN {rec["type"]} {rdata}'

    async def import_zone_file(self, zone: str, records: list[dict]) -> None:
        """Import records as BIND zone-file text via `/zones/{name}/import`
        (append mode), chunked so large sets don't build one giant request."""
        self.import_errors = 0
        url = self.base + f"/zones/{zone.rstrip('.')}/import"
        for start in range(0, len(records), self.import_chunk):
            chunk = records[start:start + self.import_chunk]
            content = "\n".join(self._zone_line(r) for r in chunk) + "\n"
            body = {"content": content, "mode": "append"}
            self.import_errors += await self._post_with_retry(
                url, body, len(chunk), check_applied=True)

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint("127.0.0.1", DNS_PORT)
