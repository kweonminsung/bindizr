"""BIND9 + nsupdate adapter — RFC 2136 dynamic updates via the `nsupdate` CLI.

There is no REST API: writes are `nsupdate` transactions, reads are DNS queries
(`dig`). This is the closest apples-to-apples comparison to Bindizr since both
sit in front of BIND9 — but here the update path IS the DNS server.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15356
ZONE = "bench.example"
SERVER = "127.0.0.1"


def _rdata(rec: dict) -> str:
    t = rec["type"]
    v = rec["value"]
    if t == "MX":
        return f'{rec.get("priority", 10)} {v if v.endswith(".") else v + "."}'
    if t == "TXT":
        return f'"{v}"'
    if t == "CNAME":
        return v if v.endswith(".") else v + "."
    return v


class Bind9NsupdateAdapter(DnsAdapter):
    key = "bind9_nsupdate"
    resource_services = ["bind9"]
    supports_ixfr = True

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("bind9", wait=False)
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 90) -> None:
        # Wait for SOA, then confirm the dynamic-update path works before returning
        # so prepopulation never races a cold server. Probe failures are retried
        # (not fatal) until the timeout.
        for _ in range(timeout * 2):
            code, _out = await self._dig(ZONE, "SOA")
            if code:
                probe = await self._nsupdate(
                    "update add probe0.bench.example. 10 A 127.0.0.1\n"
                    "update delete probe0.bench.example. A\n")
                if probe:
                    return
            await asyncio.sleep(0.5)
        raise RuntimeError("BIND9 (nsupdate) did not become ready")

    async def teardown(self) -> None:
        self.compose.down()

    async def _dig(self, name: str, rtype: str) -> tuple[bool, str]:
        proc = await asyncio.create_subprocess_exec(
            "dig", f"@{SERVER}", "-p", str(DNS_PORT), name, rtype, "+short",
            "+tries=1", "+time=3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        text = out.decode().strip()
        return (bool(text), text)

    async def _nsupdate(self, script: str, retries: int = 5) -> bool:
        header = f"server {SERVER} {DNS_PORT}\nzone {ZONE}\n"
        payload = (header + script + "send\n").encode()
        delay = 0.05
        for attempt in range(retries + 1):
            proc = await asyncio.create_subprocess_exec(
                "nsupdate", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate(payload)
            if proc.returncode == 0:
                return True
            self._last_err = (err or b"").decode(errors="replace").strip()
            # REFUSED can be transient while BIND flushes its journal; back off.
            if attempt < retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.5)
        return False

    @staticmethod
    def _fqdn(name: str) -> str:
        return f"{name}.{ZONE}."

    async def create_zone(self, zone: str) -> None:
        return  # primary zone already exists

    async def delete_zone(self, zone: str) -> None:
        return

    async def create_record(self, zone: str, rec: dict) -> str:
        fqdn = self._fqdn(rec["name"])
        ok = await self._nsupdate(
            f'update add {fqdn} {rec.get("ttl", 3600)} {rec["type"]} {_rdata(rec)}\n')
        if not ok:
            raise RuntimeError(f"nsupdate add failed: {getattr(self, '_last_err', '')!r} "
                               f"rec={rec['type']} {_rdata(rec)}")
        return f'{fqdn}|{rec["type"]}'

    async def get_record(self, zone: str, handle: str) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        ok, _ = await self._dig(fqdn, rtype)
        return ok

    async def update_record(self, zone: str, handle: str, rec: dict) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        return await self._nsupdate(
            f"update delete {fqdn} {rtype}\n"
            f'update add {fqdn} {rec.get("ttl", 3600)} {rtype} {_rdata({**rec, "type": rtype})}\n')

    async def delete_record(self, zone: str, handle: str) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        return await self._nsupdate(f"update delete {fqdn} {rtype}\n")

    def dns_endpoint(self) -> Endpoint:
        return Endpoint(SERVER, DNS_PORT)
