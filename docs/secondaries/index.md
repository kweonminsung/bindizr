# Secondary Servers

A secondary answers client DNS queries using zones transferred from Bindizr.
It follows Bindizr's **catalog zone** to discover which zones to serve and
receives NOTIFY when their records change.

The examples below assume Bindizr listens on `127.0.0.1:5300` and the
secondary on port 53. For servers on different hosts, use reachable addresses
and allow DNS traffic between them over TCP and UDP.

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

Register the secondary with `bindizr secondary create` before expecting
NOTIFY or unsigned transfers. Set the same `dns.catalog_zone_name` in Bindizr
and the secondary; independent Bindizr deployments feeding one secondary need
distinct catalog names. See [Secondaries CLI](../cli/secondaries.md) and
[Configuration](../configuration.md).

## Signing the transfers

The registered address authorizes a secondary by where it connects from,
which is all a loopback pair needs. Where the secondary is elsewhere, give it a TSIG
key in a role that holds `zone:transfer` in every zone, then name it on the
secondary's primary reference. Bindizr answers under that key and each server
page shows the syntax.

```bash
bindizr role create secondaries
bindizr role grant secondaries --actions zone:transfer
bindizr tsig-key create xfr-key --role secondaries
```

!!! note "The grant must cover every zone"

    Leave out `--zone`: a grant naming one zone does not reach the catalog
    zone, and a catalog transfer signed by a key without `zone:transfer` in
    every zone is refused. See
    [Access Control](../cli/access-control.md#secondaries-pulling-over-tsig).

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

| Command | Checks |
| --- | --- |
| `bindizr doctor` | Installation health and catalog synchronization |
| `bindizr zone status <zone>` | The member zone's serial on each secondary |
| `bindizr secondary check <name>` | One secondary's catalog serial and NOTIFY acceptance |
| `bindizr secondary transfers <name>` | Latest transfers, refusals, and failures |

A synchronized catalog does not guarantee that every member zone loaded.
Check the zone's status as well; each server page includes its own inspection
command. See [Checking a secondary](../cli/secondaries.md#checking-a-secondary).
