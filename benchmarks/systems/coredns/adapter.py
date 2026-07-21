"""CoreDNS adapter — authoritative zone served from a file the adapter rewrites.

CoreDNS has no management API and no RFC 2136 dynamic update, so writes work the
way CoreDNS is actually operated: rewrite the zone file and let the `file` plugin
pick it up on its mtime poll (`reload 1s` in the Corefile). There is no immediate
reload signal (no `rndc reload` equivalent), so every write costs up to one poll
interval. That reload latency — not record throughput — dominates CoreDNS's
write-path numbers, which is why it only joins the bulk benchmark (where the cost
is paid once for the whole set) and not the per-record CRUD/propagation ones.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15359
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/zones/bench.example.zone"


def _rdata(rec: dict) -> str:
    t, v = rec["type"], rec["value"]
    if t == "MX":
        return f'{rec.get("priority", 10)} {v if v.endswith(".") else v + "."}'
    if t == "TXT":
        return f'"{v}"'
    if t == "CNAME":
        return v if v.endswith(".") else v + "."
    return v


class CoreDnsAdapter(DnsAdapter):
    key = "coredns"
    resource_services = ["coredns"]
    # The `transfer` plugin serves AXFR but CoreDNS keeps no journal, so an IXFR
    # request is answered with a full transfer.
    supports_ixfr = False

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)
        self.records: dict[str, dict] = {}
        self.serial = 1
        self.cid: str | None = None

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("coredns", wait=False)
        self.cid = self.compose.container_id("coredns")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        for _ in range(timeout * 2):
            if await self._soa_serial() is not None:
                return
            await asyncio.sleep(0.5)
        raise RuntimeError("CoreDNS did not become ready")

    async def teardown(self) -> None:
        self.compose.down()

    async def _dig(self, name: str, rtype: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{SERVER}", "-p", str(DNS_PORT), name, rtype, "+short",
            "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        return out.decode().strip()

    async def _soa_serial(self) -> int | None:
        out = await self._dig(ZONE, "SOA")
        parts = out.split()
        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                return None
        return None

    def _zone_text(self) -> str:
        lines = [
            "$TTL 3600",
            f"@ IN SOA ns1.{ZONE}. admin.{ZONE}. ( {self.serial} 3600 600 604800 3600 )",
            f"@ IN NS ns1.{ZONE}.",
            "ns1 IN A 127.0.0.1",
        ]
        for rec in self.records.values():
            lines.append(f'{rec["name"]} {rec.get("ttl", 3600)} IN {rec["type"]} {_rdata(rec)}')
        return "\n".join(lines) + "\n"

    async def _flush_and_reload(self, timeout: float = 30.0) -> bool:
        """Rewrite the zone file, then wait until CoreDNS's poll has picked it up
        (confirmed by the SOA serial advancing) so callers observe a settled zone."""
        self.serial += 1
        with tempfile.NamedTemporaryFile("w", suffix=".zone", delete=False) as fh:
            fh.write(self._zone_text())
            tmp = fh.name
        os.chmod(tmp, 0o644)  # docker cp preserves perms; CoreDNS must be able to read it
        proc = await asyncio.create_subprocess_exec(
            "docker", "cp", tmp, f"{self.cid}:{ZONE_PATH}",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.communicate()
        Path(tmp).unlink(missing_ok=True)
        if proc.returncode != 0:
            return False

        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            got = await self._soa_serial()
            if got is not None and got >= self.serial:
                return True
            await asyncio.sleep(0.1)
        return False

    async def create_zone(self, zone: str) -> None:
        return  # the zone is declared in the Corefile

    async def delete_zone(self, zone: str) -> None:
        self.records.clear()

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Write the whole set in one rewrite so the reload cost is paid once."""
        self.bulk_errors = 0
        for rec in records:
            self.records[f'{rec["name"]}|{rec["type"]}'] = rec
        if not await self._flush_and_reload():
            self.bulk_errors = len(records)

    async def create_record(self, zone: str, rec: dict) -> str:
        handle = f'{rec["name"]}|{rec["type"]}'
        self.records[handle] = rec
        await self._flush_and_reload()
        return handle

    async def get_record(self, zone: str, handle: str) -> bool:
        name, rtype = handle.rsplit("|", 1)
        return bool(await self._dig(f"{name}.{ZONE}", rtype))

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        self.records[handle] = {**self.records.get(handle, {}), **rec}
        return await self._flush_and_reload()

    async def delete_record(self, zone: str, handle: str) -> bool:
        self.records.pop(handle, None)
        return await self._flush_and_reload()

    def dns_endpoint(self) -> Endpoint:
        return Endpoint(SERVER, DNS_PORT)
