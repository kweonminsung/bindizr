"""BIND9 + rndc adapter — manage records by rewriting the zone file and running
`rndc reload`.

This models the classic file-based BIND workflow. Per-record CRUD is expensive
(each op = full file rewrite + reload), which is exactly why it is used only for
bulk-oriented benchmarks (B2) and propagation (B3). `bulk_import` writes the
whole zone once and reloads a single time — where this approach is strongest.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15357
ZONE = "bench.example"
SERVER = "127.0.0.1"
ZONE_PATH = "/var/cache/bind/bench.example.zone"


def _rdata(rec: dict) -> str:
    t, v = rec["type"], rec["value"]
    if t == "MX":
        return f'{rec.get("priority", 10)} {v if v.endswith(".") else v + "."}'
    if t == "TXT":
        return f'"{v}"'
    if t == "CNAME":
        return v if v.endswith(".") else v + "."
    return v


class Bind9RndcAdapter(DnsAdapter):
    key = "bind9_rndc"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)
        self.records: dict[str, dict] = {}
        self.serial = 2
        self.cid: str | None = None

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("bind9", wait=False)
        self.cid = self.compose.container_id("bind9")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 60) -> None:
        for _ in range(timeout * 2):
            proc = await asyncio.create_subprocess_exec(
                "dig", f"@{SERVER}", "-p", str(DNS_PORT), ZONE, "SOA", "+short",
                "+tries=1", "+time=3",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await proc.communicate()
            if out.decode().strip():
                return
            await asyncio.sleep(0.5)
        raise RuntimeError("BIND9 (rndc) did not become ready")

    async def teardown(self) -> None:
        self.compose.down()

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

    async def _run(self, *cmd: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.communicate()
        return proc.returncode == 0

    async def _flush_and_reload(self) -> bool:
        import os

        self.serial += 1
        with tempfile.NamedTemporaryFile("w", suffix=".zone", delete=False) as fh:
            fh.write(self._zone_text())
            tmp = fh.name
        # Make world-readable so BIND (uid 53) can read the root-owned copy.
        os.chmod(tmp, 0o644)
        ok = await self._run("docker", "cp", tmp, f"{self.cid}:{ZONE_PATH}")
        Path(tmp).unlink(missing_ok=True)
        if not ok:
            return False
        return await self._run("docker", "exec", self.cid, "rndc", "reload", ZONE)

    async def create_zone(self, zone: str) -> None:
        return

    async def delete_zone(self, zone: str) -> None:
        self.records.clear()
        await self._flush_and_reload()

    async def create_record(self, zone: str, rec: dict) -> str:
        handle = f'{rec["name"]}|{rec["type"]}'
        self.records[handle] = rec
        await self._flush_and_reload()
        return handle

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        for rec in records:
            self.records[f'{rec["name"]}|{rec["type"]}'] = rec
        await self._flush_and_reload()

    async def get_record(self, zone: str, handle: str) -> bool:
        name, rtype = handle.rsplit("|", 1)
        fqdn = f"{name}.{ZONE}"
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{SERVER}", "-p", str(DNS_PORT), fqdn, rtype, "+short",
            "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        return bool(out.decode().strip())

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        self.records[handle] = {**self.records.get(handle, {}), **rec}
        return await self._flush_and_reload()

    async def delete_record(self, zone: str, handle: str) -> bool:
        self.records.pop(handle, None)
        return await self._flush_and_reload()

    def dns_endpoint(self) -> Endpoint:
        return Endpoint(SERVER, DNS_PORT)
