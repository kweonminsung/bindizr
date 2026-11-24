"""Use Bindizr's control plane with an NSD secondary to isolate secondary-server costs.
"""
from __future__ import annotations

from systems.bindizr.adapter import BindizrAdapter


class BindizrNsdAdapter(BindizrAdapter):
    key = "bindizr_nsd"
    secondary_service = "nsd"
