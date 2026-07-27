"""Deterministic DNS record dataset generator.

Given a fixed seed, produces the *same* records every run so results are
reproducible across systems and machines. Output is a list of plain dicts that
each adapter maps onto its own API/format.

Record shape:
    {"name": "host000123", "type": "A", "value": "10.b.c.d", "ttl": 3600}

Type mix mirrors a realistic zone: mostly A/AAAA, some CNAME/TXT/MX.
"""
from __future__ import annotations

import random
from typing import Iterator

ZONE = "bench.example."


def _ip4(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _ip6(rng: random.Random) -> str:
    return "2001:db8::" + ":".join(f"{rng.randint(0, 0xffff):x}" for _ in range(3))


def generate(count: int, seed: int, zone: str = ZONE) -> list[dict]:
    return list(iter_records(count, seed, zone))


def iter_records(count: int, seed: int, zone: str = ZONE) -> Iterator[dict]:
    rng = random.Random(seed)
    for i in range(count):
        name = f"host{i:06d}"
        roll = rng.random()
        if roll < 0.60:
            rec = {"name": name, "type": "A", "value": _ip4(rng), "ttl": 3600}
        elif roll < 0.80:
            rec = {"name": name, "type": "AAAA", "value": _ip6(rng), "ttl": 3600}
        elif roll < 0.90:
            target = f"host{rng.randint(0, max(i, 1)):06d}.{zone}"
            rec = {"name": name, "type": "CNAME", "value": target, "ttl": 3600}
        elif roll < 0.97:
            rec = {"name": name, "type": "TXT", "value": f"v=bench{i}", "ttl": 3600}
        else:
            rec = {"name": name, "type": "MX", "value": f"mail{i % 5}.{zone}",
                   "ttl": 3600, "priority": 10}
        yield rec


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", default="-")
    args = ap.parse_args()
    data = generate(args.count, args.seed)
    if args.out == "-":
        print(json.dumps(data[:10], indent=2))
        print(f"... {len(data)} records (showing first 10)")
    else:
        with open(args.out, "w") as fh:
            json.dump(data, fh)
