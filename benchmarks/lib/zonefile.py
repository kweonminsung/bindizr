"""DNS text shared by benchmark zone files and dynamic updates."""
from __future__ import annotations

from collections.abc import Iterable


def build_record_data(record: dict) -> str:
    """Build record data for a benchmark zone file or nsupdate command."""
    record_type, value = record["type"], record["value"]

    if record_type == "MX":
        return f'{record.get("priority", 10)} {value if value.endswith(".") else value + "."}'

    if record_type == "TXT":
        return f'"{value}"'

    if record_type == "CNAME":
        return value if value.endswith(".") else value + "."

    return value


def build_zone_file(zone: str, serial: int, records: Iterable[dict]) -> str:
    """Build a benchmark zone file, preserving the supplied record order."""
    lines = [
        "$TTL 3600",
        f"@ IN SOA ns1.{zone}. admin.{zone}. ( {serial} 3600 600 604800 3600 )",
        f"@ IN NS ns1.{zone}.",
        "ns1 IN A 127.0.0.1",
    ]

    for record in records:
        lines.append(
            f'{record["name"]} {record.get("ttl", 3600)} IN {record["type"]} '
            f'{build_record_data(record)}')

    return "\n".join(lines) + "\n"
