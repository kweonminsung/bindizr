"""Common adapter interface every system-under-test implements.

A benchmark runner talks only to this interface, so the same workload runs
unchanged against Bindizr, PowerDNS, Technitium, and BIND9+nsupdate/rndc.

Semantics notes:
- `create_record` returns an opaque handle (id or name) used by get/update/delete.
- For systems without a REST record API (BIND9+nsupdate/rndc) the handle is the
  record name; update/delete operate by name.
- `dns_endpoint()` returns (host, port) of a resolver that answers queries for
  the managed zone — for Bindizr this is a BIND9 secondary, proving the control
  plane is outside the data plane.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass
class Endpoint:
    host: str
    port: int


class DnsAdapter(abc.ABC):
    key: str = "base"
    #: container/compose service names whose resources should be measured
    resource_services: list[str] = []

    def __init__(self, cfg: dict, project: str):
        self.cfg = cfg
        self.project = project

    # --- lifecycle ----------------------------------------------------------
    @abc.abstractmethod
    async def setup(self) -> None:
        """Bring up containers and wait until ready."""

    @abc.abstractmethod
    async def teardown(self) -> None:
        """Tear down containers and volumes."""

    # --- zone ---------------------------------------------------------------
    @abc.abstractmethod
    async def create_zone(self, zone: str) -> None: ...

    @abc.abstractmethod
    async def delete_zone(self, zone: str) -> None: ...

    # --- record CRUD --------------------------------------------------------
    @abc.abstractmethod
    async def create_record(self, zone: str, rec: dict) -> str:
        """Create a record; return a handle for later get/update/delete."""

    @abc.abstractmethod
    async def get_record(self, zone: str, handle: str) -> bool:
        """Fetch a record; return True on success."""

    @abc.abstractmethod
    async def update_record(self, zone: str, handle: str, rec: dict) -> bool: ...

    @abc.abstractmethod
    async def delete_record(self, zone: str, handle: str) -> bool: ...

    # --- bulk ---------------------------------------------------------------
    #: concurrency used by the default bulk_import
    bulk_concurrency: int = 32

    async def bulk_import(self, zone: str, records: list[dict]) -> None:
        """Default bulk = concurrent creates via a fixed worker pool (memory-safe
        for very large record sets); adapters may override for batch APIs.

        Per-record failures are retried (a real importer would retry transient
        backend contention, e.g. SQLite write locks) and, if still failing,
        counted in `self.bulk_errors` rather than aborting the whole import."""
        import asyncio

        self.bulk_errors = 0
        queue: asyncio.Queue[int] = asyncio.Queue()
        for i in range(len(records)):
            queue.put_nowait(i)

        async def worker():
            while True:
                try:
                    i = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                delay = 0.02
                for attempt in range(4):
                    try:
                        await self.create_record(zone, records[i])
                        break
                    except Exception:
                        if attempt == 3:
                            self.bulk_errors += 1
                        else:
                            await asyncio.sleep(delay)
                            delay = min(delay * 2, 0.5)

        await asyncio.gather(*(worker() for _ in range(self.bulk_concurrency)))

    #: populated by bulk_import
    bulk_errors: int = 0

    # --- DNS data plane -----------------------------------------------------
    @abc.abstractmethod
    def dns_endpoint(self) -> Endpoint:
        """Resolver that answers queries for the managed zone."""

    def xfr_endpoint(self) -> Endpoint:
        """Server that answers AXFR/IXFR for the managed zone (defaults to DNS)."""
        return self.dns_endpoint()

    # --- capability flags ---------------------------------------------------
    supports_ixfr: bool = True
    supports_bulk_api: bool = False
