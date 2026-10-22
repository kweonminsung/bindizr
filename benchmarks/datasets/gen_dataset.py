"""Generate identical DNS records for a fixed seed across all benchmark systems.

Emit adapter-neutral dictionaries such as {"name": "host000123", "type": "A",
"value": "10.b.c.d", "ttl": 3600}, mostly A/AAAA with CNAME/TXT/MX.
"""
from __future__ import annotations

import random

ZONE = "bench.example."


def _generate_ipv4(rng: random.Random) -> str:
    """Generate an IPv4 value for a benchmark record."""
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _generate_ipv6(rng: random.Random) -> str:
    """Generate an IPv6 value for a benchmark record."""
    return "2001:db8::" + ":".join(f"{rng.randint(0, 0xffff):x}" for _ in range(3))


def generate(count: int, seed: int, zone: str = ZONE) -> list[dict]:
    """Generate a reproducible list of benchmark records."""
    rng = random.Random(seed)
    records = []

    for i in range(count):
        name = f"host{i:06d}"
        roll = rng.random()

        if roll < 0.60:
            record = {"name": name, "type": "A", "value": _generate_ipv4(rng), "ttl": 3600}
        elif roll < 0.80:
            record = {"name": name, "type": "AAAA", "value": _generate_ipv6(rng), "ttl": 3600}
        elif roll < 0.90:
            target = f"host{rng.randint(0, max(i, 1)):06d}.{zone}"
            record = {"name": name, "type": "CNAME", "value": target, "ttl": 3600}
        elif roll < 0.97:
            record = {"name": name, "type": "TXT", "value": f"v=bench{i}", "ttl": 3600}
        else:
            record = {"name": name, "type": "MX", "value": f"mail{i % 5}.{zone}",
                   "ttl": 3600, "priority": 10}

        records.append(record)

    return records


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
