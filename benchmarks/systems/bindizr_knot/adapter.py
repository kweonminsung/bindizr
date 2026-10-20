"""Use Bindizr's control plane with a Knot secondary to isolate secondary-server costs.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from bindizr.adapter import BindizrAdapter  # noqa: E402


class BindizrKnotAdapter(BindizrAdapter):
    key = "bindizr_knot"
    secondary_service = "knot"
