"""Use Bindizr's control plane with a PowerDNS secondary to isolate secondary-server costs.
"""
from __future__ import annotations

from systems.bindizr.adapter import BindizrAdapter


class BindizrPdnsAdapter(BindizrAdapter):
    key = "bindizr_pdns"
    secondary_service = "pdns"
    # PowerDNS pulls member zones with AXFR: it asks for no incremental
    # transfer, so Benchmark 5 measures full transfers for this pair.
    supports_ixfr = False
