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

## Disabled secondaries

`--enabled false` keeps the row and stops everything else: no NOTIFY, no
unsigned transfer, no probe. It is the switch for a server under maintenance,
or one being replaced whose address should stay on record.

Secondaries are also manageable over the HTTP API (`/secondaries`) — see the
[API Reference](https://kweonminsung.github.io/bindizr/api/).
