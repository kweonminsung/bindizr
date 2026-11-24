"""Drive PowerDNS Authoritative's record API with PATCH REPLACE/DELETE per (name, type).

Handles use "<fqdn>|<TYPE>"; the same server manages and answers records.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import aiohttp

from adapters.base import DnsAdapter, Endpoint
from lib import docker

HERE = Path(__file__).resolve().parent

API_PORT = 18081
DNS_PORT = 15354
API_KEY = "benchkey"

# PowerDNS 4.9 stalls above roughly ten API connections; queue client-side to avoid measuring SYN retries.
API_MAX_CONNECTIONS = 8


def _content(record: dict) -> str:
    """Render a benchmark record in the PowerDNS API content format."""
    value = record["value"]
    if record["type"] == "MX":
        return f'{record.get("priority", 10)} {value}'
    if record["type"] == "TXT":
        return value if value.startswith('"') else f'"{value}"'
    return value


class PowerDnsAdapter(DnsAdapter):
    key = "powerdns"
    resource_services = ["powerdns"]
    supports_ixfr = False  # gsqlite3 IXFR is limited; exercised via AXFR fallback

    def __init__(self, config: dict, project: str):
        """Initialize the adapter with its benchmark configuration and project."""
        super().__init__(config, project)
        self.base = f"http://localhost:{API_PORT}/api/v1/servers/localhost"
        self.headers = {"X-API-Key": API_KEY}
        self.session: aiohttp.ClientSession | None = None
        self.compose = docker.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        """Start the benchmark system and wait for it to become ready."""
        await self.compose.up("powerdns", wait=True)
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            connector=aiohttp.TCPConnector(limit=API_MAX_CONNECTIONS))
        await self._wait_api()

    async def _wait_api(self, timeout: int = 60) -> None:
        """Wait until the system API is ready."""
        for _ in range(timeout * 2):
            try:
                async with self.session.get(self.base, timeout=aiohttp.ClientTimeout(total=2)) as response:
                    if response.status == 200:
                        return
            except Exception:
                pass
            await asyncio.sleep(0.5)

        raise RuntimeError("PowerDNS API did not become ready")

    async def teardown(self) -> None:
        """Stop the benchmark system and release its resources."""
        try:
            if self.session:
                await self.session.close()
        finally:
            await self.compose.down()

    @staticmethod
    def _fqdn(zone_name: str, name: str) -> str:
        """Qualify a record owner with its zone name."""
        return f"{name}.{zone_name.rstrip('.')}."

    async def create_zone(self, zone_name: str) -> None:
        """Create the zone used by the benchmark."""
        fqdn_zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        body = {
            "name": fqdn_zone_name,
            "kind": "Native",
            "nameservers": [f"ns1.{fqdn_zone_name}"],
        }

        async with self.session.post(self.base + "/zones", json=body) as response:
            if response.status not in (200, 201, 409):
                raise RuntimeError(f"create_zone {response.status}: {await response.text()}")

    async def delete_zone(self, zone_name: str) -> None:
        """Remove the benchmark zone and its records."""
        fqdn_zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        async with self.session.delete(self.base + f"/zones/{fqdn_zone_name}") as response:
            if response.status not in (200, 204, 404):
                raise RuntimeError(f"delete_zone {response.status}: {await response.text()}")

    async def _patch(self, zone_name: str, name: str, record_type: str, changetype: str,
                     record: dict | None) -> bool:
        """Submit a record-group change through the PowerDNS API."""
        fqdn_zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        rrset = {"name": self._fqdn(zone_name, name), "type": record_type, "changetype": changetype}

        if changetype == "REPLACE":
            rrset["ttl"] = record.get("ttl", 3600)
            rrset["records"] = [{"content": _content(record), "disabled": False}]

        async with self.session.patch(self.base + f"/zones/{fqdn_zone_name}", json={"rrsets": [rrset]}) as response:
            await response.read()
            return response.status in (200, 204)

    async def create_record(self, zone_name: str, record: dict) -> str:
        """Create a record and return its adapter-specific handle."""
        if not await self._patch(zone_name, record["name"], record["type"], "REPLACE", record):
            raise RuntimeError(f'create_record failed for {record["name"]} {record["type"]}')
        return f'{self._fqdn(zone_name, record["name"])}|{record["type"]}'

    async def import_records(self, zone_name: str, records: list[dict]) -> None:
        """Import records in batched PowerDNS PATCH requests for throughput."""
        fqdn_zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        batch = 500

        for start in range(0, len(records), batch):
            rrsets = [{
                "name": self._fqdn(zone_name, record["name"]),
                "type": record["type"],
                "ttl": record.get("ttl", 3600),
                "changetype": "REPLACE",
                "records": [{"content": _content(record), "disabled": False}],
            } for record in records[start:start + batch]]

            async with self.session.patch(self.base + f"/zones/{fqdn_zone_name}",
                                          json={"rrsets": rrsets}) as response:
                if response.status not in (200, 204):
                    raise RuntimeError(f"bulk PATCH {response.status}: {await response.text()}")

    async def get_record(self, zone_name: str, handle: str) -> bool:
        """Check whether the record identified by the handle is present."""
        fqdn, record_type = handle.rsplit("|", 1)
        fqdn_zone_name = zone_name if zone_name.endswith(".") else zone_name + "."
        params = {"rrset_name": fqdn, "rrset_type": record_type}
        async with self.session.get(self.base + f"/zones/{fqdn_zone_name}", params=params) as response:
            if response.status == 404:
                return False
            if response.status != 200:
                raise RuntimeError(f"get_record {response.status}: {await response.text()}")
            data = await response.json()
            return any(
                rrset["name"].rstrip(".").lower() == fqdn.rstrip(".").lower()
                and rrset["type"].upper() == record_type.upper()
                and rrset["records"]
                for rrset in data["rrsets"]
            )

    async def update_record(self, zone_name: str, handle: str, record: dict) -> bool:
        """Replace the record identified by the handle with the supplied value."""
        fqdn, record_type = handle.rsplit("|", 1)
        name = fqdn[: -(len(zone_name.rstrip(".")) + 2)]
        return await self._patch(zone_name, name, record_type, "REPLACE", {**record, "type": record_type})

    async def delete_record(self, zone_name: str, handle: str) -> bool:
        """Delete the record identified by the handle."""
        fqdn, record_type = handle.rsplit("|", 1)
        name = fqdn[: -(len(zone_name.rstrip(".")) + 2)]
        return await self._patch(zone_name, name, record_type, "DELETE", None)

    def dns_endpoint(self) -> Endpoint:
        """Return the DNS endpoint that serves the managed zone."""
        return Endpoint("127.0.0.1", DNS_PORT)
