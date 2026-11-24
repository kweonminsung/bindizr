"""Use Bindizr's control plane with a Knot secondary to isolate secondary-server costs.
"""
from __future__ import annotations

from systems.bindizr.adapter import BindizrAdapter


class BindizrKnotAdapter(BindizrAdapter):
    key = "bindizr_knot"
    secondary_service = "knot"
