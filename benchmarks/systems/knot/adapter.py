"""Knot DNS adapter — RFC 2136 dynamic updates against a Knot primary.

Knot is a full participant: it has a real write plane (DDNS) and keeps a journal,
so it serves true IXFR deltas as well as AXFR. Writes go through `nsupdate`, the
same mechanism as the BIND9+nsupdate system, which makes the two directly
comparable; bulk loads batch many updates into one UPDATE transaction, which is
how an operator would actually load a zone over DDNS.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from adapters.base import DnsAdapter, Endpoint  # noqa: E402
from lib import dockerutil  # noqa: E402

DNS_PORT = 15360
ZONE = "bench.example"
SERVER = "127.0.0.1"


def _rdata(rec: dict) -> str:
    t, v = rec["type"], rec["value"]
    if t == "MX":
        return f'{rec.get("priority", 10)} {v if v.endswith(".") else v + "."}'
    if t == "TXT":
        return f'"{v}"'
    if t == "CNAME":
        return v if v.endswith(".") else v + "."
    return v


class KnotAdapter(DnsAdapter):
    key = "knot"
    resource_services = ["knot"]
    supports_ixfr = True
    # Updates per UPDATE transaction. A DNS message is capped at 64 KB over TCP,
    # so keep the batch well under that while still amortizing the round trip.
    update_batch = 500

    def __init__(self, cfg: dict, project: str):
        super().__init__(cfg, project)
        self.compose = dockerutil.Compose(HERE / "compose.yml", project)
        self.cid: str | None = None

    async def setup(self) -> None:
        self.compose.down()  # clean slate: remove any leftovers from a prior run
        self.compose.up("knot", wait=False)
        self.cid = self.compose.container_id("knot")
        await self._wait_dns()

    async def _wait_dns(self, timeout: int = 90) -> None:
        # Confirm the dynamic-update path works, not just that SOA answers, so
        # prepopulation never races a cold server.
        for _ in range(timeout * 2):
            code, _out = await self._dig(ZONE, "SOA")
            if code:
                probe = await self._nsupdate(
                    "update add probe0.bench.example. 10 A 127.0.0.1\n"
                    "update delete probe0.bench.example. A\n")
                if probe:
                    return
            await asyncio.sleep(0.5)
        raise RuntimeError("Knot DNS did not become ready")

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
            # A busy zone (journal flush) can transiently refuse; back off.
            if attempt < retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 0.5)
        return False

    async def _knotc(self, *args: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.cid, "knotc", *args,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await proc.communicate()
        if proc.returncode != 0:
            self._last_err = (err or b"").decode(errors="replace").strip()
        return proc.returncode == 0

    @staticmethod
    def _fqdn(name: str) -> str:
        return f"{name}.{ZONE}."

    async def create_zone(self, zone: str) -> None:
        return  # the zone is declared in knot.conf

    async def delete_zone(self, zone: str) -> None:
        """Drop the zone contents and reload the pristine zone file.

        The zone itself is declared in knot.conf and cannot be removed over
        DDNS. `+zonefile` is deliberately left out of the purge: `zonefile-sync:
        -1` means Knot never writes back, so that file is still the seed and the
        reload restores the bare apex from it.
        """
        if not self.cid:
            return
        await self._knotc("-f", "zone-purge", "+expire", "+journal", "+timers", ZONE)
        await self._knotc("zone-reload", ZONE)
        await self._wait_dns()

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Batch adds into as few UPDATE transactions as the message size allows."""
        self.bulk_errors = 0
        for start in range(0, len(records), self.update_batch):
            chunk = records[start:start + self.update_batch]
            script = "".join(
                f'update add {self._fqdn(r["name"])} {r.get("ttl", 3600)} '
                f'{r["type"]} {_rdata(r)}\n'
                for r in chunk
            )
            if not await self._nsupdate(script):
                self.bulk_errors += len(chunk)

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
            f'update add {fqdn} {rec.get("ttl", 3600)} {rtype} '
            f'{_rdata({**rec, "type": rtype})}\n')

    async def delete_record(self, zone: str, handle: str) -> bool:
        fqdn, rtype = handle.rsplit("|", 1)
        return await self._nsupdate(f"update delete {fqdn} {rtype}\n")

    def dns_endpoint(self) -> Endpoint:
        return Endpoint(SERVER, DNS_PORT)
