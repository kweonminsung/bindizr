"""Map a system key to its adapter instance."""
from __future__ import annotations

from importlib import import_module


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
    """Return whether this system runs the Bindizr control plane."""
    return key in BINDIZR_SYSTEMS


def build_adapter(key: str, config: dict, project: str, **kwargs):
    """Construct the adapter for a benchmark system and project."""
    class_name = _CLASS[key]
    module = import_module(f"systems.{key}.adapter")
    cls = getattr(module, class_name)
    return cls(config, project, **kwargs)
