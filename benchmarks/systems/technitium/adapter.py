"""Drive Technitium's token-authenticated GET API, which returns {"status":"ok", ...}.

Handles encode (domain, type, value) because records have no server-side ids.
The same server manages and answers records.
"""
from __future__ import annotations

import asyncio
from ipaddress import ip_address
from pathlib import Path

import aiohttp

from adapters.base import DnsAdapter, Endpoint
from lib import docker

HERE = Path(__file__).resolve().parent

API_PORT = 15380
DNS_PORT = 15355
SEP = "||"


class TechnitiumAdapter(DnsAdapter):
    key = "technitium"
    resource_services = ["technitium"]
    supports_ixfr = True

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project)
        self.base = f"http://localhost:{API_PORT}/api"
        self.token: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self.compose = docker.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        await self.compose.up("technitium", wait=False)
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
        try:
            if self.session:
                await self.session.close()
        finally:
            await self.compose.down()

    async def _get(self, path: str, params: dict,
                   absent_messages: tuple[str, ...] = ()) -> dict | None:
        """Require HTTP and API success, with None for explicitly allowed absent resources."""
        params = {"token": self.token, **params}
        async with self.session.get(self.base + path, params=params) as response:
            if response.status != 200:
                raise RuntimeError(f"{path} {response.status}: {await response.text()}")
            data = await response.json()

        status = data["status"]
        if status == "ok":
            return data
        if status == "error" and data.get("errorMessage") in absent_messages:
            return None
        raise RuntimeError(f"{path} {status}: {data.get('errorMessage', 'no error message')}")

    @staticmethod
    def _fqdn(zone_name: str, name: str) -> str:
        """Qualify a record owner with its zone name."""
        return f"{name}.{zone_name.rstrip('.')}"

    async def create_zone(self, zone_name: str) -> None:
        """Create the zone used by the benchmark."""
        await self._get("/zones/create", {"zone": zone_name.rstrip("."), "type": "Primary"})
        # Enable AXFR/IXFR for Benchmarks 4 & 5.
        await self._get("/zones/options/set",
                        {"zone": zone_name.rstrip("."), "zoneTransfer": "Allow"})

    async def delete_zone(self, zone_name: str) -> None:
        """Remove the benchmark zone and its records."""
        zone_name = zone_name.rstrip(".")
        await self._get("/zones/delete", {"zone": zone_name},
                        absent_messages=(f"No such zone was found: {zone_name}",))

    def _build_record_params(self, record: dict) -> dict:
        """Map a benchmark record value to Technitium request parameters."""
        record_type = record["type"]
        value = record["value"]

        if record_type in ("A", "AAAA"):
            return {"ipAddress": value}

        if record_type == "CNAME":
            return {"cname": value.rstrip(".")}

        if record_type == "TXT":
            return {"text": value}

        if record_type == "MX":
            return {"exchange": value.rstrip("."), "preference": record.get("priority", 10)}

        return {"rdata": value}

    def _encode_record_handle(self, zone_name: str, record: dict) -> str:
        """Encode the record identity and value into a reusable adapter handle."""
        return SEP.join([self._fqdn(zone_name, record["name"]), record["type"], record["value"],
                         str(record.get("priority", ""))])

    def _decode_record_handle(self, handle: str) -> dict:
        """Decode a record handle into its stored identity and value."""
        fqdn, record_type, value_and_priority = handle.split(SEP, 2)
        value, prio = value_and_priority.rsplit(SEP, 1)
        record = {"fqdn": fqdn, "type": record_type, "value": value}
        if prio:
            record["priority"] = int(prio)
        return record

    async def create_record(self, zone_name: str, record: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        params = {
            "domain": self._fqdn(zone_name, record["name"]),
            "zone": zone_name.rstrip("."),
            "type": record["type"],
            "ttl": record.get("ttl", 3600),
            **self._build_record_params(record),
        }

        await self._get("/zones/records/add", params)
        return self._encode_record_handle(zone_name, record)

    async def get_record(self, zone_name: str, handle: str) -> bool:
        """Check whether the owner, type and data encoded in the handle are present."""
        record = self._decode_record_handle(handle)
        fqdn = record["fqdn"]
        data = await self._get("/zones/records/get",
                               {"domain": fqdn, "zone": zone_name.rstrip("."), "listZone": "false"},
                               absent_messages=(f"No such zone was found for: {fqdn}",))
        if data is None:
            return False
        return any(self._matches_record(record, found) for found in data["response"]["records"])

    def _matches_record(self, record: dict, found: dict) -> bool:
        """Compare record data without depending on a domain or IP's spelling."""
        record_type = record["type"]
        if (found["name"].rstrip(".").lower() != record["fqdn"].rstrip(".").lower()
                or found["type"].upper() != record_type):
            return False

        data = found["rData"]
        expected = self._build_record_params(record)
        if record_type in ("A", "AAAA"):
            return ip_address(data["ipAddress"]) == ip_address(expected["ipAddress"])
        if record_type == "CNAME":
            return data["cname"].rstrip(".").lower() == expected["cname"].lower()
        if record_type == "MX":
            return (data["exchange"].rstrip(".").lower() == expected["exchange"].lower()
                    and data["preference"] == expected["preference"])
        return all(data.get(key) == value for key, value in expected.items())

    async def update_record(self, zone_name: str, handle: str, record: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        existing_record = self._decode_record_handle(handle)
        record_type = existing_record["type"]
        params = {
            "domain": existing_record["fqdn"],
            "zone": zone_name.rstrip("."),
            "type": record_type,
            "ttl": record.get("ttl", 3600),
        }
        # Technitium update needs the current value plus new* value fields.
        value_params = self._build_record_params({"type": record_type, "value": existing_record["value"],
                                 "priority": existing_record.get("priority", 10)})
        params.update(value_params)

        for key, value in value_params.items():
            params["new" + key[0].upper() + key[1:]] = value

        await self._get("/zones/records/update", params)
        return True

    async def delete_record(self, zone_name: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        existing_record = self._decode_record_handle(handle)
        params = {
            "domain": existing_record["fqdn"],
            "zone": zone_name.rstrip("."),
            "type": existing_record["type"],
            **self._build_record_params({"type": existing_record["type"], "value": existing_record["value"],
                                  "priority": existing_record.get("priority", 10)}),
        }

        data = await self._get("/zones/records/delete", params, absent_messages=(
            "Cannot delete record: no such record exists.",
            f"No such zone was found for: {existing_record['fqdn']}",
        ))
        return data is not None

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint("127.0.0.1", DNS_PORT)
