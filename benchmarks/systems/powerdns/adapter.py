"""PowerDNS Authoritative adapter — drives the REST API (RRset-based).

PowerDNS has no per-record id: records are grouped into RRsets keyed by
(name, type) and mutated with PATCH REPLACE/DELETE. A "handle" here is
"<fqdn>|<TYPE>". The same server answers DNS queries, so PowerDNS is an
integrated (control + data plane) system, unlike Bindizr.
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

API_PORT = 18081
DNS_PORT = 15354
API_KEY = "benchkey"

# pdns-auth's webserver stops accepting somewhere above ten concurrent
# connections and 4.9 exposes no setting to raise that, so the surplus stalls on
# the client's TCP SYN retransmit (1s, then 2s) — which measures the retransmit
# timer, not the API. Cap the pool so a wider workload queues client-side.
API_MAX_CONNECTIONS = 8


def _content(rec: dict) -> str:
    v = rec["value"]
    if rec["type"] == "MX":
        return f'{rec.get("priority", 10)} {v}'
    if rec["type"] == "TXT":
        return v if v.startswith('"') else f'"{v}"'
    return v


class PowerDnsAdapter(DnsAdapter):
    key = "powerdns"
    resource_services = ["powerdns"]
    supports_ixfr = False  # gsqlite3 IXFR is limited; exercised via AXFR fallback

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.base = f"http://localhost:{API_PORT}/api/v1/servers/localhost"
        self.headers = {"X-API-Key": API_KEY}
        self.session: aiohttp.ClientSession | None = None
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("powerdns", wait=True)
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            connector=aiohttp.TCPConnector(limit=API_MAX_CONNECTIONS))
        await self._wait_api()

    async def _wait_api(self, timeout: int = 60) -> None:
        for _ in range(timeout * 2):
            try:
                async with self.session.get(self.base, timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        return
            except Exception:
                pass
            await asyncio.sleep(0.5)
        raise RuntimeError("PowerDNS API did not become ready")

    async def teardown(self) -> None:
        if self.session:
            await self.session.close()
        self.compose.down()

    @staticmethod
    def _fqdn(zone: str, name: str) -> str:
        return f"{name}.{zone.rstrip('.')}."

    async def create_zone(self, zone: str) -> None:
        z = zone if zone.endswith(".") else zone + "."
        body = {
            "name": z,
            "kind": "Native",
            "nameservers": [f"ns1.{z}"],
        }
        async with self.session.post(self.base + "/zones", json=body) as r:
            if r.status not in (201, 200, 409, 422):
                raise RuntimeError(f"create_zone {r.status}: {await r.text()}")

    async def delete_zone(self, zone: str) -> None:
        z = zone if zone.endswith(".") else zone + "."
        async with self.session.delete(self.base + f"/zones/{z}") as r:
            await r.read()

    async def _patch(self, zone: str, name: str, rtype: str, changetype: str,
                     rec: dict | None) -> bool:
        z = zone if zone.endswith(".") else zone + "."
        rrset = {"name": self._fqdn(zone, name), "type": rtype, "changetype": changetype}
        if changetype == "REPLACE":
            rrset["ttl"] = rec.get("ttl", 3600)
            rrset["records"] = [{"content": _content(rec), "disabled": False}]
        async with self.session.patch(self.base + f"/zones/{z}", json={"rrsets": [rrset]}) as r:
            await r.read()
            return r.status in (200, 204)

    async def create_record(self, zone: str, rec: dict) -> str:
        if not await self._patch(zone, rec["name"], rec["type"], "REPLACE", rec):
            raise RuntimeError(f'create_record failed for {rec["name"]} {rec["type"]}')
        return f'{self._fqdn(zone, rec["name"])}|{rec["type"]}'

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        # PowerDNS accepts many RRsets in one PATCH; batch for throughput.
        z = zone if zone.endswith(".") else zone + "."
        batch = 500
        for start in range(0, len(records), batch):
            rrsets = [{
                "name": self._fqdn(zone, r["name"]),
                "type": r["type"],
                "ttl": r.get("ttl", 3600),
                "changetype": "REPLACE",
                "records": [{"content": _content(r), "disabled": False}],
            } for r in records[start:start + batch]]
            async with self.session.patch(self.base + f"/zones/{z}",
                                          json={"rrsets": rrsets}) as resp:
                if resp.status not in (200, 204):
                    raise RuntimeError(f"bulk PATCH {resp.status}: {await resp.text()}")

    async def get_record(self, zone: str, handle: str) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        z = zone if zone.endswith(".") else zone + "."
        url = self.base + f"/zones/{z}?rrset_name={fqdn}&rrset_type={rtype}"
        async with self.session.get(url) as r:
            if r.status != 200:
                return False
            data = await r.json()
            return bool(data.get("rrsets"))

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        name = fqdn[: -(len(zone.rstrip(".")) + 2)]
        return await self._patch(zone, name, rtype, "REPLACE", {**rec, "type": rtype})

    async def delete_record(self, zone: str, handle: str) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        name = fqdn[: -(len(zone.rstrip(".")) + 2)]
        return await self._patch(zone, name, rtype, "DELETE", None)

    def dns_endpoint(self) -> Endpoint:
        return Endpoint("127.0.0.1", DNS_PORT)
