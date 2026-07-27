"""Minimal async UDP DNS query load generator (no external deps).

Builds raw DNS query packets and drives them over per-worker connected UDP
sockets, so it can push far more QPS than forking `dig`. Used by Benchmark 9 to
measure query throughput and latency across servers.
"""
from __future__ import annotations

import asyncio
import itertools
import socket
import struct
import time

from .metrics import LatencyRecorder

QTYPE = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15}


def build_query(qid: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", qid & 0xFFFF, 0x0000, 1, 0, 0, 0)  # RD=0 (auth)
    qname = b"".join(
        bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


def _ancount(resp: bytes) -> int:
    if len(resp) < 12:
        return 0
    return struct.unpack(">H", resp[6:8])[0]


async def query_load(server: str, port: int, names: list[str], qtype: int,
                     concurrency: int, duration_secs: float,
                     warmup_secs: float = 0.0) -> LatencyRecorder:
    rec = LatencyRecorder()
    clock = time.monotonic
    warmup_until = clock() + warmup_secs
    measure_end = warmup_until + duration_secs
    rec.started_at = warmup_until
    loop = asyncio.get_event_loop()
    counter = itertools.count()
    n = len(names)

    async def worker() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect((server, port))
        try:
            while True:
                now = clock()
                if now >= measure_end:
                    return
                seq = next(counter)
                name = names[seq % n]
                pkt = build_query(seq, name, qtype)
                t0 = clock()
                ok = False
                try:
                    await loop.sock_sendall(sock, pkt)
                    # Discard replies to earlier queries: one timed-out query
                    # would otherwise leave every later read off by one, since
                    # the socket is reused for the worker's whole run.
                    while True:
                        resp = await asyncio.wait_for(
                            loop.sock_recv(sock, 512), timeout=2.0)
                        if resp[:2] == pkt[:2]:
                            break
                    ok = _ancount(resp) > 0
                except Exception:
                    ok = False
                t1 = clock()
                if t1 >= warmup_until:
                    rec.record(t1 - t0, ok=ok)
        finally:
            sock.close()

    await asyncio.gather(*[worker() for _ in range(concurrency)])
    rec.ended_at = clock()
    return rec
