"""Drive Technitium's token-authenticated GET API, which returns {"status":"ok", ...}.

Handles encode (domain, type, value) because records have no server-side ids.
The same server manages and answers records.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import aiohttp

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import docker  # noqa: E402

API_PORT = 15380
DNS_PORT = 15355
SEP = "||"


class TechnitiumAdapter(DnsAdapter):
    key = "technitium"
    resource_services = ["technitium"]
    supports_ixfr = False

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project)
        self.base = f"http://localhost:{API_PORT}/api"
        self.token: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self.compose = docker.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("technitium", wait=False)
        # Technitium compresses responses with brotli when offered; aiohttp has no
        # built-in brotli decoder, so restrict Accept-Encoding to what it handles.
        self.session = aiohttp.ClientSession(headers={"Accept-Encoding": "gzip, deflate"})
        await self._login()

    async def _login(self, timeout: int = 90) -> None:
        """Authenticate with the Technitium API and save its token."""
        for _ in range(timeout * 2):
            try:
                url = self.base + "/user/login?user=admin&pass=admin&includeInfo=false"
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("status") == "ok":
                            self.token = data["token"]
                            return
            except Exception:
                pass

            await asyncio.sleep(0.5)

        raise RuntimeError("Technitium API did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        if self.session:
            await self.session.close()
        self.compose.down()

    async def _get(self, path: str, params: dict) -> dict:
        """Send an authenticated request to the Technitium API."""
        params = {"token": self.token, **params}
        async with self.session.get(self.base + path, params=params) as response:
            return await response.json()

    @staticmethod
    def _fqdn(zone: str, name: str) -> str:
        """Qualify a record owner with its zone name."""
        return f"{name}.{zone.rstrip('.')}"

    async def create_zone(self, zone: str) -> None:
        """Create the zone used by the benchmark."""
        await self._get("/zones/create", {"zone": zone.rstrip("."), "type": "Primary"})
        # Enable AXFR/IXFR for Benchmarks 4 & 5.
        await self._get("/zones/options/set",
                        {"zone": zone.rstrip("."), "zoneTransfer": "Allow"})

    async def delete_zone(self, zone: str) -> None:
        """Remove the benchmark zone and its records."""
        await self._get("/zones/delete", {"zone": zone.rstrip(".")})

    def _build_record_params(self, record: dict) -> dict:
        """Map a benchmark record value to Technitium request parameters."""
        t = record["type"]
        v = record["value"]

        if t in ("A", "AAAA"):
            return {"ipAddress": v}

        if t == "CNAME":
            return {"cname": v.rstrip(".")}

        if t == "TXT":
            return {"text": v}

        if t == "MX":
            return {"exchange": v.rstrip("."), "preference": record.get("priority", 10)}

        return {"rdata": v}

    def _encode_record_handle(self, zone: str, record: dict) -> str:
        """Encode the record identity and value into a reusable adapter handle."""
        return SEP.join([self._fqdn(zone, record["name"]), record["type"], record["value"],
                         str(record.get("priority", ""))])

    def _decode_record_handle(self, handle: str) -> dict:
        """Decode a record handle into its stored identity and value."""
        fqdn, rtype, value, prio = handle.split(SEP)
        record = {"fqdn": fqdn, "type": rtype, "value": value}
        if prio:
            record["priority"] = int(prio)
        return record

    async def create_record(self, zone: str, record: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        params = {
            "domain": self._fqdn(zone, record["name"]),
            "zone": zone.rstrip("."),
            "type": record["type"],
            "ttl": record.get("ttl", 3600),
            **self._build_record_params(record),
        }

        data = await self._get("/zones/records/add", params)

        if data.get("status") != "ok":
            raise RuntimeError(f"add record failed: {data}")

        return self._encode_record_handle(zone, record)

    async def get_record(self, zone: str, handle: str) -> bool:
        """Fetch the handle's record information and report API success."""
        existing_record = self._decode_record_handle(handle)
        data = await self._get("/zones/records/get",
                               {"domain": existing_record["fqdn"], "zone": zone.rstrip("."),
                                "listZone": "false"})
        return data.get("status") == "ok"

    async def update_record(self, zone: str, handle: str, record: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        existing_record = self._decode_record_handle(handle)
        t = existing_record["type"]
        params = {
            "domain": existing_record["fqdn"],
            "zone": zone.rstrip("."),
            "type": t,
            "ttl": record.get("ttl", 3600),
        }
        # Technitium update needs the current value plus new* value fields.
        vp = self._build_record_params({"type": t, "value": existing_record["value"],
                                 "priority": existing_record.get("priority", 10)})
        params.update(vp)

        for k, val in vp.items():
            params["new" + k[0].upper() + k[1:]] = val

        data = await self._get("/zones/records/update", params)

        return data.get("status") == "ok"

    async def delete_record(self, zone: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        existing_record = self._decode_record_handle(handle)
        params = {
            "domain": existing_record["fqdn"],
            "zone": zone.rstrip("."),
            "type": existing_record["type"],
            **self._build_record_params({"type": existing_record["type"], "value": existing_record["value"],
                                  "priority": existing_record.get("priority", 10)}),
        }

        data = await self._get("/zones/records/delete", params)

        return data.get("status") == "ok"

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint("127.0.0.1", DNS_PORT)
