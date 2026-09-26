# Secondaries

The secondaries are the servers Bindizr feeds. A registered secondary
receives NOTIFY for every zone, may pull zones unsigned from its address, and
is probed by `zone status` and `doctor` for the serial it serves. One list
decides all three, so a server that hears a change is also the one allowed to
pull it. The list lives in the database beside the zones and is managed at
runtime: a change takes effect on the next NOTIFY or transfer, with no reload.

```bash
# Register a secondary by name and host[:port]; 53 is the port when left out
$ bindizr secondary create ns2 --address 10.0.0.14
$ bindizr secondary create ns3 --address ns3.example.net:53

# List them, disabled ones included
$ bindizr secondary list

# Show one
$ bindizr secondary get ns2

# Move it, or stop feeding it without forgetting it
$ bindizr secondary update ns2 --address 10.0.0.15
$ bindizr secondary update ns2 --enabled false

# Ask one what it serves and whether it takes a NOTIFY
$ bindizr secondary check ns2

# Forget it
$ bindizr secondary delete ns2
```

A secondary Bindizr does not know gets no NOTIFY and has its transfers
refused, which is the first thing to check when a new server never picks up
a zone — see [Troubleshooting](../troubleshooting.md#secondaries).

## Addresses

An address is `host[:port]` — `192.0.2.7`, `[2001:db8::7]:53`,
`ns2.example.net:53`. It is stored with the port spelled out and a hostname
lowercased, so one server has one row however it is written; registering an
address a second time, under another name, is refused.

A hostname is resolved when used, not when registered, so a changed address
is picked up on its own, within a minute. Where the address is not stable, a
Kubernetes pod or a DHCP lease, register the secondary by a name that follows
it; a name that no longer resolves to it refuses its next transfer.

## Signed transfers

The address authorizes a secondary by where it connects from, which is all a
loopback pair needs. A transfer signed with a TSIG key is authorized by the
key instead — see [TSIG Keys](tsig-keys.md#signing-zone-transfers) — but
NOTIFY still goes only to the registered secondaries, so a keyed secondary is
registered all the same.

## Signed NOTIFY

NOTIFY goes out unsigned unless the secondary is registered with a key:

```bash
$ bindizr secondary create ns2 --address 10.0.0.14 --notify-key notify-key
$ bindizr secondary update ns2 --notify-key notify-key
$ bindizr secondary update ns2 --notify-key ""        # unsigned again
```

Every NOTIFY to that server is then signed with the key and the signature on
its answer checked, so a server that accepts NOTIFY only under a key can be
fed: `allow-notify { key notify-key; }` in BIND, `allow-notify: 10.0.0.5
notify-key` in NSD, a `notify` ACL with the key in Knot. The key is a TSIG
key like any other — see [TSIG Keys](tsig-keys.md) — and needs no grant,
since a NOTIFY carries no zone data; the same key may also sign the
transfers. A key a secondary signs with cannot be deleted until the
secondary is moved off it.

## Disabled secondaries

`--enabled false` keeps the row and stops everything else: no NOTIFY, no
unsigned transfer, no probe. It is the switch for a server under maintenance,
or one being replaced whose address should stay on record.

## Checking a secondary

Each section above is something that can go wrong on its own: a name that
stopped resolving, a serial the server never pulled, a key it does not
accept. `bindizr secondary check <name>` asks one server about all of them,
the questions `doctor` asks every enabled one, and prints one line per
answer:

```text
$ bindizr secondary check ns2
Secondary ns2: ns2.example.net:53 (enabled, NOTIFY signed with notify-key)
Resolves to: 10.0.0.14:53
Catalog zone catalog.bindizr: in sync at serial 42
NOTIFY to 10.0.0.14:53: accepted
```

The first line is what is registered, the second what the address resolves
to right now, which is where a pod that moved shows up. The catalog line
compares the serial the secondary serves with the one Bindizr serves,
reported as `in sync`, `lagging`, `ahead`, or `unreachable` exactly as
`zone status` does per zone; when Bindizr's own listener did not answer,
the report says so on a line of its own and the secondary's serial stands
alone as `reachable`. The NOTIFY is a real one for the catalog zone, signed
with the secondary's key when it has one, so a key the server does not
accept shows up here. A disabled secondary can be checked too, which is how
to see whether it is ready before enabling it again.

The command exits non-zero when any line fails, so a script can branch on
it; `-o json` carries the same fields.

Secondaries are also manageable over the HTTP API (`/secondaries`, with
`POST /secondaries/{name}/check` for the check) — see the
[API Reference](https://kweonminsung.github.io/bindizr/api/).
