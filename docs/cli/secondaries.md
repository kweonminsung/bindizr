# Secondaries

Register each secondary so it receives NOTIFY, may transfer zones unsigned
from its address, and appears in `zone status` and `doctor`. Changes take
effect on the next NOTIFY or transfer without a reload.

```bash
# Register a secondary by name and host[:port]; 53 is the port when left out
bindizr secondary create ns2 --address 10.0.0.14
bindizr secondary create ns3 --address ns3.example.net:53

# List them, disabled ones included
bindizr secondary list

# Show one
bindizr secondary get ns2

# Move it, or stop feeding it without forgetting it
bindizr secondary update ns2 --address 10.0.0.15
bindizr secondary update ns2 --enabled false

# Ask one what it serves and whether it takes a NOTIFY
bindizr secondary check ns2

# Forget it
bindizr secondary delete ns2
```

A secondary that is not registered receives no NOTIFY and cannot transfer
unsigned. Check registration first when a new server does not pick up a zone;
see [Troubleshooting](../troubleshooting.md#secondaries).

## Addresses

Use `host[:port]`, such as `192.0.2.7`, `[2001:db8::7]:53`, or
`ns2.example.net:53`. Port 53 is the default. Equivalent addresses cannot be
registered twice under different names.

A hostname is resolved when used, not when registered, so a changed address
is picked up on its own, within a minute. Where the address is not stable, a
Kubernetes pod or a DHCP lease, register the secondary by a name that follows
it; a name that no longer resolves to it refuses its next transfer.

## Signed transfers

The address authorizes a secondary by where it connects from, which is all a
loopback pair needs. A transfer signed with a TSIG key is authorized by the
key instead — see [Signing zone transfers](advanced.md#signing-zone-transfers) — but
NOTIFY still goes only to the registered secondaries, so a keyed secondary is
registered all the same.

## Signed NOTIFY

NOTIFY goes out unsigned unless the secondary is registered with a key:

```bash
bindizr secondary create ns2 --address 10.0.0.14 --notify-key notify-key
bindizr secondary update ns2 --notify-key notify-key
bindizr secondary update ns2 --notify-key ""        # unsigned again
```

Every NOTIFY to that server is then signed with the key and the signature on
its answer checked, so a server that accepts NOTIFY only under a key can be
fed: `allow-notify { key notify-key; }` in BIND, `allow-notify: 10.0.0.5
notify-key` in NSD, a `notify` ACL with the key in Knot. The key is a TSIG
key like any other — see [Access Control](access-control.md#tsig-keys) — and
its role needs no grant, since a NOTIFY carries no zone data; the same key may also sign the
transfers. A key a secondary signs with cannot be deleted until the
secondary is moved off it.

## Disabled secondaries

`--enabled false` keeps the row and stops everything else: no NOTIFY, no
unsigned transfer, no probe. It is the switch for a server under maintenance,
or one being replaced whose address should stay on record.

## Checking a secondary

`bindizr secondary check <name>` checks address resolution, catalog
synchronization, and NOTIFY acceptance. It also works on a disabled secondary,
so you can check one before enabling it again:

```text
$ bindizr secondary check ns2
Secondary ns2: ns2.example.net:53 (enabled, NOTIFY signed with notify-key)
Resolves to: 10.0.0.14:53
Catalog zone catalog.bindizr: in sync at serial 42
NOTIFY to 10.0.0.14:53: accepted
Transfers: 12 zones: 11 IXFR delta, 0 IXFR full, 1 AXFR, 0 refused, 0 failed
```

The catalog status compares the two serials: `in sync`, `lagging`, `ahead`,
or `unreachable`. If Bindizr's listener cannot be queried, a responding
secondary is reported only as `reachable`. The check sends a real catalog
NOTIFY, signed when a key is configured. Transfer counts summarize
[what it pulled](#what-it-pulled); they do not determine the check result.

The command exits non-zero when any line fails, so a script can branch on
it; `-o json` carries the same fields.

## What it pulled

Bindizr keeps the latest transfer it served each client address per zone,
refusals and failures included. `bindizr secondary transfers <name>` reads
it back for the addresses the secondary resolves to, `zone status` shows the
same transfer per zone in its `LAST-TRANSFER` column, and `doctor` prints the
summary per secondary:

```text
$ bindizr secondary transfers ns2
ZONE            TRANSFER     TRANSPORT  SERIAL  ADDRESS     AT                    ERROR
example.com     IXFR delta   TLS        42      10.0.0.14   2026-09-28T09:41:05Z  -
example.net     AXFR         TLS        7       10.0.0.14   2026-09-28T09:40:58Z  -
internal.test   refused      TCP        -       10.0.0.14   2026-09-28T09:40:58Z  TSIG key 'xfr-key' is not granted 'zone:transfer' in zone 'internal.test'
3 zones: 1 IXFR delta, 0 IXFR full, 1 AXFR, 1 refused, 0 failed
```

`IXFR full` is an IXFR answered with the whole zone because the journal no
longer held the delta; `refused` and `failed` carry the reason in `ERROR`.
`TRANSPORT` says whether the request came over plain TCP or TLS, and `zone
status` marks a TLS transfer with `over TLS`.
`--zone` narrows the list and `--limit` shortens it; the summary counts every
zone regardless. The rows are in the database, so a restart keeps them and
deleting a zone drops them.

Secondaries are also manageable over the HTTP API (`/secondaries`, with
`POST /secondaries/{name}/check` for the check and
`GET /secondaries/{name}/transfers` for the transfers) — see the
[API Reference](https://kweonminsung.github.io/bindizr/api/).
