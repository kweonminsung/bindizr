"""Use Bindizr's control plane with an NSD secondary to isolate secondary-server costs.
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
