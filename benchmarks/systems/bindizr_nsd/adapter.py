"""Bindizr with an NSD secondary.

Same control plane as `bindizr`; only the server answering queries differs, so
the pair of runs isolates what the secondary choice costs.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from bindizr.adapter import BindizrAdapter  # noqa: E402


class BindizrNsdAdapter(BindizrAdapter):
    key = "bindizr_nsd"
    secondary_service = "nsd"
