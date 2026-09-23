# Secondary Servers

A secondary is the name server clients actually query. Bindizr is its
primary: it keeps the zone data, hands it over by zone transfer (AXFR sends
a whole zone, IXFR the changes since a serial), and sends a NOTIFY whenever
a zone changed. Which zones to hold, the secondary learns from Bindizr's
**catalog zone** (RFC 9432): a zone whose records list the other zones. All
of that is standard DNS, so the secondary can be any server that understands
catalog zones.

| | Catalog zones | Verified on | Notes |
| --- | --- | --- | --- |
| [BIND](bind.md) | 9.18 or newer | 9.20 | |
| [Knot DNS](knot.md) | 3.1 or newer | 3.4 | |
| [NSD](nsd.md) | 4.9 or newer | 4.12 | |
| [PowerDNS](powerdns.md) | 4.7 or newer | 4.9 | AXFR only; [does not sign member transfers](powerdns.md#tsig-does-not-reach-member-zones) |

"Verified on" is the version Bindizr's own interoperability run covers:
catalog provisioning, NOTIFY-driven updates, record and zone deletion, and
TSIG-signed transfers.

## What the secondary has to do

Two things, whatever the implementation:

1. **Transfer the catalog zone from Bindizr.** `dns.catalog_zone_name` names it
   — `catalog.bindizr` unless you changed it — and the secondary declares it
   like any other secondary zone, with Bindizr as its primary.
2. **Provision the zones the catalog names**, pulling each from that same
   primary. Every implementation has its own word for the template those zones
   are created from; the per-server pages below spell it.

Create a zone in Bindizr and it appears in the catalog; the secondary picks it
up on the NOTIFY that follows, with no configuration of its own. Delete the
zone and it goes away the same way.

Bindizr's side is two settings, and the first is the one a new setup
forgets: a secondary Bindizr does not know gets no NOTIFY and has its
transfers refused. See [Configuration](../configuration.md#secondaries):

| Setting | What it does |
| --- | --- |
| `dns.secondary_addrs` | Who receives NOTIFY, and the only clients allowed to pull a zone unsigned: `host[:port]` entries, a hostname resolved when used |
| `dns.catalog_zone_name` | The catalog zone's name. A secondary holds one zone per name, so two Bindizr instances feeding one secondary need two names |

## Signing the transfers

The address list authorizes a secondary by where it connects from, which is
all a loopback pair needs. Where the secondary is elsewhere, give it a TSIG
key: create one with
[`bindizr tsig-key create <name> --global`](../cli/tsig-keys.md), then name it
on the secondary's primary reference. Bindizr answers under that key and each
server page shows the syntax.

!!! note "`--global` is required, not a convenience"

    A scoped key is granted zones you created, and the catalog zone is not
    one of them: a catalog transfer signed by a scoped key is refused.

!!! warning "PowerDNS does not sign member transfers"

    BIND, Knot, and NSD reuse the catalog zone's key for the member zones that
    catalog provisions. PowerDNS does not — see
    [PowerDNS](powerdns.md#tsig-does-not-reach-member-zones).

Bindizr logs every transfer with `signed=true` or `signed=false`, so whether a
key was actually used is visible rather than assumed:

```text
XFR TCP query: zone="example.com", qtype=Rtype::AXFR, from=10.0.0.14, signed=false
```

## Checking that it worked

`bindizr zone status <zone>` reports the serial each secondary serves next to
Bindizr's own, and `bindizr doctor` probes every address in
`dns.secondary_addrs` for the catalog zone. Both work regardless of which
implementation answers. Each server page also gives that server's own command
for inspecting a zone it learned from the catalog.
