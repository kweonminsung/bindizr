# Secondary Servers

A secondary answers client DNS queries using zones transferred from Bindizr.
It follows Bindizr's **catalog zone** to discover which zones to serve and
receives NOTIFY when their records change. A server without catalog zone
support can still be a secondary; each zone is then declared on it by hand.

![DNS servers verified as Bindizr secondaries](../assets/secondaries.svg)

The examples below assume Bindizr listens on `127.0.0.1:5300` and the
secondary on port 53. For servers on different hosts, use reachable addresses
and allow DNS traffic between them over TCP and UDP.

## Catalog zone secondaries

These learn every zone from the catalog: create a zone in Bindizr and it
appears on them, delete it and it goes away.

| | Catalog zones | Verified on | Notes |
| --- | --- | --- | --- |
| [BIND](bind.md) | 9.18 or newer | 9.18, 9.20 | |
| [Knot DNS](knot.md) | 3.1 or newer | 3.2, 3.4, 3.5, 3.6 | |
| [NSD](nsd.md) | 4.9 or newer | 4.14 | |
| [PowerDNS](powerdns.md) | 4.7 or newer | 4.7, 4.8, 4.9, 5.0, 5.1 | AXFR only; [does not sign member transfers](powerdns.md#tsig-does-not-reach-member-zones) |
| [Technitium DNS](technitium.md) | Secondary Catalog zone | 15.5 | |
| [CoreDNS](coredns.md) | 1.14.6 or newer | 1.14.6, 1.14.7 | AXFR only, no TSIG; [NSEC3-signed zones refused](coredns.md#nsec3-signed-zones-are-refused) |

## Per-zone secondaries

These transfer, take NOTIFY, and serve the zones they are given, but do not
read the catalog, so each zone Bindizr serves is added on the server.

| | Verified on | Notes |
| --- | --- | --- |
| [Windows Server DNS](windows.md) | 2019, 2022, 2025 | No TSIG for zone transfers |
| [YADIFA](yadifa.md) | 2.6 | |
| [NSD before 4.9](nsd.md#nsd-before-49) | 4.6 | |
| [Unbound](unbound.md) | 1.25 | No TSIG; [changes arrive on SOA refresh](unbound.md#changes-arrive-on-the-soa-refresh) |
| [CoreDNS before 1.14.6](coredns.md#coredns-before-1146) | 1.14.4 | AXFR only, no TSIG; [NSEC3-signed zones refused](coredns.md#nsec3-signed-zones-are-refused) |

"Verified on" is the version Bindizr's own interoperability run covers:
initial transfer of a zone spanning several messages, NOTIFY-driven updates
as IXFR deltas where the server asks for them, record deletion, a
DNSSEC-signed zone, TSIG-signed transfers where the server supports them, and,
for catalog zone secondaries, zone creation and deletion.

## What the secondary has to do

A catalog zone secondary does two things, whatever the implementation:

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

A per-zone secondary declares each zone instead, with Bindizr as its primary,
and is registered the same way. Bindizr still sends it NOTIFY for the catalog
zone, which it refuses or leaves unanswered, so `secondary check` reports a
failure for it; the zones it does serve are unaffected.

## Signing the transfers

The registered address authorizes a secondary by where it connects from,
which is all a loopback pair needs. Where the secondary is elsewhere, give it a TSIG
key in a role that holds `zone:transfer` in all zones, then name it on the
secondary's primary reference. Bindizr answers under that key and each server
page shows the syntax.

```bash
bindizr role create secondaries
bindizr role grant secondaries --actions zone:transfer
bindizr tsig-key create xfr-key --role secondaries
```

!!! note "The grant must cover all zones"

    Leave out `--zone`: a grant naming one zone does not reach the catalog
    zone, and a catalog transfer signed by a key without `zone:transfer` in
    all zones are refused. See
    [Access Control](../cli/access-control.md#secondaries-pulling-over-tsig).

!!! warning "PowerDNS does not sign member transfers"

    BIND, Knot, NSD, and Technitium reuse the catalog zone's key for the
    member zones that catalog provisions. PowerDNS does not — see
    [PowerDNS](powerdns.md#tsig-does-not-reach-member-zones).

Bindizr logs every transfer with `signed=true` or `signed=false`, so whether a
key was actually used is visible rather than assumed:

```text
XFR TCP query: zone="example.com", qtype=Rtype::AXFR, from=10.0.0.14, signed=false
```

A transfer over TLS logs as `XFR TLS query`, and `secondary transfers` lists
the transport beside each one. Over TLS the key and the registered address
are required together, as RFC 9103, Section 7.5 asks of a server without
mutual TLS; either alone is refused there. A query the listener does not
serve, an update included, is refused with extended DNS error 21, Not
Supported (Section 7.8).
Every listener answers an EDNS query with an OPT record and keeps a UDP
answer within the size the query advertised, 512 octets without EDNS. Over
TCP and TLS the OPT also carries the connection's idle timeout
(`dns.tcp_idle_timeout_secs`, 30 seconds by default) as edns-tcp-keepalive
(RFC 7828).

## Transfers over TLS

With `[dns.tls]` set (see [Configuration](../configuration.md)), Bindizr
serves transfers over TLS (XoT, RFC 9103) on a second port, 853 by default.
The certificate must carry the name the secondary connects to, and a renewed
pair is re-read by `bindizr config reload`. Over TLS a
secondary must be registered *and* sign with a key (RFC 9103, Section 7.5);
the plain listener takes either alone. [BIND](bind.md#transfers-over-tls)
9.18.10, [Knot DNS](knot.md#transfers-over-tls) 3.4, and
[NSD](nsd.md#transfers-over-tls) 4.3.7 or newer speak it. `secondary
transfers` shows the transport, and the log says `XFR TLS query`. Once every
secondary pulls over TLS, `dns.transfer.require_tls = true` refuses a
transfer over plain TCP or UDP, as RFC 9103, Section 11 asks of a zone
whose transfers are XoT; SOA queries keep answering on every listener.

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
