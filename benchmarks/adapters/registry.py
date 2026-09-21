"""Map a system key to its adapter instance."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYSTEMS = ROOT / "systems"


def _load_adapter_module(key: str):
    """Load the adapter module for the requested system key."""
    path = SYSTEMS / key / "adapter.py"
    if not path.exists():
        raise FileNotFoundError(f"no adapter for system '{key}' at {path}")
    spec = importlib.util.spec_from_file_location(f"systems.{key}.adapter", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_CLASS = {
    "bindizr": "BindizrAdapter",
    "bindizr_knot": "BindizrKnotAdapter",
    "bindizr_nsd": "BindizrNsdAdapter",
    "bindizr_pdns": "BindizrPdnsAdapter",
    "powerdns": "PowerDnsAdapter",
    "technitium": "TechnitiumAdapter",
    "bind9_nsupdate": "Bind9NsupdateAdapter",
    "bind9_rndc": "Bind9RndcAdapter",
    "bind9_native": "Bind9NativeAdapter",
    "coredns": "CoreDnsAdapter",
    "knot": "KnotAdapter",
}


#: The systems running the Bindizr control plane, whichever secondary serves
#: queries for them. They take the same adapter keywords.
BINDIZR_SYSTEMS = ("bindizr", "bindizr_knot", "bindizr_nsd", "bindizr_pdns")


def is_bindizr(key: str) -> bool:
    """Whether this system runs the Bindizr control plane."""
    return key in BINDIZR_SYSTEMS


def build(key: str, cfg: dict, project: str, **kwargs):
    """Construct the adapter for a benchmark system and project."""
    mod = _load_adapter_module(key)
    cls = getattr(mod, _CLASS[key])
    return cls(cfg, project, **kwargs)
