"""Technitium DNS Server adapter — drives the token-authenticated HTTP API.

Technitium's API is GET-based with query params and returns JSON
{"status":"ok", ...}. Records are identified by (domain, type, value); a handle
here encodes all three so delete/update work without server-side ids. The same
server answers DNS queries (integrated).
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

API_PORT = 15380
DNS_PORT = 15355
SEP = "||"


class TechnitiumAdapter(DnsAdapter):
    key = "technitium"
    resource_services = ["technitium"]
    supports_ixfr = False

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.base = f"http://localhost:{API_PORT}/api"
        self.token: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("technitium", wait=False)
        # Technitium compresses responses with brotli when offered; aiohttp has no
        # built-in brotli decoder, so restrict Accept-Encoding to what it handles.
        self.session = aiohttp.ClientSession(headers={"Accept-Encoding": "gzip, deflate"})
        await self._login()

    async def _login(self, timeout: int = 90) -> None:
        for _ in range(timeout * 2):
            try:
                url = self.base + "/user/login?user=admin&pass=admin&includeInfo=false"
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "ok":
                            self.token = data["token"]
                            return
            except Exception:
                pass
            await asyncio.sleep(0.5)
        raise RuntimeError("Technitium API did not become ready")

    async def teardown(self) -> None:
        if self.session:
            await self.session.close()
        self.compose.down()

    async def _get(self, path: str, params: dict) -> dict:
        params = {"token": self.token, **params}
        async with self.session.get(self.base + path, params=params) as r:
            return await r.json()

    @staticmethod
    def _fqdn(zone: str, name: str) -> str:
        return f"{name}.{zone.rstrip('.')}"

    async def create_zone(self, zone: str) -> None:
        await self._get("/zones/create", {"zone": zone.rstrip("."), "type": "Primary"})
        # Enable AXFR/IXFR for Benchmarks 4 & 5.
        await self._get("/zones/options/set",
                        {"zone": zone.rstrip("."), "zoneTransfer": "Allow"})

    async def delete_zone(self, zone: str) -> None:
        await self._get("/zones/delete", {"zone": zone.rstrip(".")})

    def _value_params(self, rec: dict) -> dict:
        t = rec["type"]
        v = rec["value"]
        if t in ("A", "AAAA"):
            return {"ipAddress": v}
        if t == "CNAME":
            return {"cname": v.rstrip(".")}
        if t == "TXT":
            return {"text": v}
        if t == "MX":
            return {"exchange": v.rstrip("."), "preference": rec.get("priority", 10)}
        return {"rdata": v}

    def _handle(self, zone: str, rec: dict) -> str:
        return SEP.join([self._fqdn(zone, rec["name"]), rec["type"], rec["value"],
                         str(rec.get("priority", ""))])

    def _parse(self, handle: str) -> dict:
        fqdn, rtype, value, prio = handle.split(SEP)
        rec = {"fqdn": fqdn, "type": rtype, "value": value}
        if prio:
            rec["priority"] = int(prio)
        return rec

    async def create_record(self, zone: str, rec: dict) -> str:
        params = {
            "domain": self._fqdn(zone, rec["name"]),
            "zone": zone.rstrip("."),
            "type": rec["type"],
            "ttl": rec.get("ttl", 3600),
            **self._value_params(rec),
        }
        data = await self._get("/zones/records/add", params)
        if data.get("status") != "ok":
            raise RuntimeError(f"add record failed: {data}")
        return self._handle(zone, rec)

    async def get_record(self, zone: str, handle: str) -> bool:
        r = self._parse(handle)
        data = await self._get("/zones/records/get",
                               {"domain": r["fqdn"], "zone": zone.rstrip("."),
                                "listZone": "false"})
        return data.get("status") == "ok"

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        r = self._parse(handle)
        t = r["type"]
        params = {
            "domain": r["fqdn"],
            "zone": zone.rstrip("."),
            "type": t,
            "ttl": rec.get("ttl", 3600),
        }
        # Technitium update needs the current value plus new* value fields.
        vp = self._value_params({"type": t, "value": r["value"],
                                 "priority": r.get("priority", 10)})
        params.update(vp)
        for k, val in vp.items():
            params["new" + k[0].upper() + k[1:]] = val
        data = await self._get("/zones/records/update", params)
        return data.get("status") == "ok"

    async def delete_record(self, zone: str, handle: str) -> bool:
        r = self._parse(handle)
        params = {
            "domain": r["fqdn"],
            "zone": zone.rstrip("."),
            "type": r["type"],
            **self._value_params({"type": r["type"], "value": r["value"],
                                  "priority": r.get("priority", 10)}),
        }
        data = await self._get("/zones/records/delete", params)
        return data.get("status") == "ok"

    def dns_endpoint(self) -> Endpoint:
        return Endpoint("127.0.0.1", DNS_PORT)
