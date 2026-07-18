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


class BindizrAdapter(DnsAdapter):
    key = "bindizr"
    resource_services = ["bindizr", "bind9"]
    supports_ixfr = True
    # Bindizr exposes a native bulk-insert API and a BIND zone-file import API, so
    # it does not fall back to the base one-by-one bulk path.
    supports_bulk_api = True
    supports_zone_import = True
    # Records per request: each bulk/import batch is one server-side transaction
    # (single serial bump + NOTIFY), so batch to bound memory and transaction size.
    bulk_chunk = 2000
    import_chunk = 5000

    def __init__(self, cfg: dict, project: str, db_type: str | None = None,
                 notify_after_update: bool = True,
                 apply_mode: str | None = None,
                 apply_batch_ms: int | None = None,
                 zone_cache: bool | None = None,
                 log_level: str | None = None):
        super().__init__(cfg, project)
        # b07 passes db_type explicitly; b02/others fall back to the env knob so a
        # single benchmark can be pointed at any backend (default sqlite).
        db_type = db_type or os.environ.get("BENCH_BINDIZR_DB_TYPE", "sqlite")
        self.db_type = db_type
        # Sample the DB container that is actually under test (mysql/postgres run
        # as their own containers; sqlite is embedded in the bindizr process), so
        # Benchmark 7's per-backend CPU/mem columns include the profiled backend.
        self.resource_services = ["bindizr", "bind9"]
        if db_type == "mysql":
            self.resource_services.append("mysql")
        elif db_type == "postgresql":
            self.resource_services.append("postgres")
        self.notify_after_update = notify_after_update
        # None => Bindizr's own defaults (sync / 50 / true); see compose.yml.
        self.apply_mode = apply_mode or os.environ.get("BENCH_BINDIZR_APPLY_MODE", "sync")
        self.apply_batch_ms = apply_batch_ms if apply_batch_ms is not None else int(
            os.environ.get("BENCH_BINDIZR_APPLY_BATCH_MS", "50"))
        self.zone_cache = zone_cache if zone_cache is not None else (
            os.environ.get("BENCH_BINDIZR_ZONE_CACHE", "true").lower() == "true")
        # Raise to "debug" to surface the server's per-stage timing lines
        # (event=record_bulk_create_timing / event=zone_import_timing).
        self.log_level = log_level or os.environ.get("BENCH_BINDIZR_LOG_LEVEL", "info")
        # HTTP-level batch sizes, overridable so the JSON-bulk vs zone-import
        # comparison can be run with matched chunks — each chunk is one
        # transaction + serial bump + NOTIFY, so chunk count skews the totals.
        self.bulk_chunk = int(os.environ.get("BENCH_BINDIZR_BULK_CHUNK", str(self.bulk_chunk)))
        self.import_chunk = int(os.environ.get("BENCH_BINDIZR_IMPORT_CHUNK", str(self.import_chunk)))
        self.base = f"http://localhost:{API_PORT}"
        self.session: aiohttp.ClientSession | None = None
        env = {"BINDIZR_DB_TYPE": db_type,
               "BINDIZR_NOTIFY_AFTER_UPDATE": "true" if notify_after_update else "false",
               "BINDIZR_APPLY_MODE": self.apply_mode,
               "BINDIZR_APPLY_BATCH_MS": str(self.apply_batch_ms),
               "BINDIZR_ZONE_CACHE": "true" if self.zone_cache else "false",
               "BINDIZR_LOG_LEVEL": self.log_level}
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
        return {**self._bulk_item(rec), "zone_name": zone.rstrip(".")}

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
        body = self._bulk_item(rec)
        async with self.session.put(self.base + f"/records/{handle}", json=body) as r:
            await r.read()
            return r.status == 200

    async def delete_record(self, zone: str, handle: str) -> bool:
        async with self.session.delete(self.base + f"/records/{handle}") as r:
            await r.read()
            return r.status == 200

    def _bulk_item(self, rec: dict) -> dict:
        item = {
            "name": rec["name"],
            "record_type": rec["type"],
            "value": rec["value"],
            "ttl": rec.get("ttl", 3600),
        }
        if "priority" in rec:
            item["priority"] = rec["priority"]
        return item

    async def _post_with_retry(self, url: str, body: dict, count: int,
                               check_applied: bool = False) -> int:
        """POST `body`, retrying transient failures. Returns the number of records
        that failed after all retries (0 on success).

        The zone-import endpoint returns HTTP 200 even when validation errors
        leave `applied=false` and nothing is inserted; `check_applied` inspects
        the response so a rejected chunk counts as failed instead of a silent
        success. Rejection is deterministic, so it is not retried."""
        delay = 0.05
        for attempt in range(4):
            try:
                async with self.session.post(url, json=body) as r:
                    if r.status in (200, 201):
                        if not check_applied:
                            return 0
                        data = await r.json()
                        return 0 if data.get("applied") else count
            except Exception:
                pass
            if attempt < 3:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 1.0)
        return count

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Bulk-insert via Bindizr's `/records/bulk` API in single-transaction
        chunks (each chunk bumps the serial once and sends one NOTIFY)."""
        self.bulk_errors = 0
        url = self.base + f"/zones/{zone.rstrip('.')}/records/bulk"
        for start in range(0, len(records), self.bulk_chunk):
            chunk = records[start:start + self.bulk_chunk]
            body = {"records": [self._bulk_item(r) for r in chunk]}
            self.bulk_errors += await self._post_with_retry(url, body, len(chunk))

    def _zone_line(self, rec: dict) -> str:
        ttl = rec.get("ttl", 3600)
        rdata = rec["value"]
        if rec["type"] == "TXT":
            rdata = '"{}"'.format(rec["value"].replace("\\", "\\\\").replace('"', '\\"'))
        elif rec["type"] == "MX":
            rdata = f'{rec.get("priority", 10)} {rec["value"]}'
        return f'{rec["name"]} {ttl} IN {rec["type"]} {rdata}'

    async def import_zone_file(self, zone: str, records: list[dict]) -> None:
        """Import records as BIND zone-file text via `/zones/{name}/imports`
        (append mode), chunked so large sets don't build one giant request."""
        self.import_errors = 0
        url = self.base + f"/zones/{zone.rstrip('.')}/imports"
        for start in range(0, len(records), self.import_chunk):
            chunk = records[start:start + self.import_chunk]
            content = "\n".join(self._zone_line(r) for r in chunk) + "\n"
            body = {"content": content, "mode": "append"}
            self.import_errors += await self._post_with_retry(
                url, body, len(chunk), check_applied=True)

    def dns_endpoint(self) -> Endpoint:
        return Endpoint("127.0.0.1", DNS_PORT)
