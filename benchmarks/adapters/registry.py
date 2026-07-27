"""Map a system key to its adapter instance."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYSTEMS = ROOT / "systems"


def _load_adapter_module(key: str):
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
    "powerdns": "PowerDnsAdapter",
    "technitium": "TechnitiumAdapter",
    "bind9_nsupdate": "Bind9NsupdateAdapter",
    "bind9_rndc": "Bind9RndcAdapter",
    "bind9_native": "Bind9NativeAdapter",
    "coredns": "CoreDnsAdapter",
    "knot": "KnotAdapter",
}


def build(key: str, cfg: dict, project: str, **kwargs):
    mod = _load_adapter_module(key)
    cls = getattr(mod, _CLASS[key])
    return cls(cfg, project, **kwargs)
