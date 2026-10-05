# Unbound

Unbound's `auth-zone` transfers a zone and answers for it authoritatively,
but does not read catalog zones, so each zone Bindizr serves is declared on
it. Bindizr's interoperability run covers Unbound 1.25.

## 1. Register the secondary in Bindizr

Register the server's address so it may transfer zones. This example uses a
server on the same host, listening on port 53:

```bash
# An Unbound on this host; elsewhere, its address or hostname
sudo bindizr secondary create unbound --address 127.0.0.1
```

## 2. Add the zones

Declare each zone in `unbound.conf` with Bindizr as its primary:

```text
auth-zone:
    name: "example.com"
    primary: 127.0.0.1@5300
    allow-notify: 127.0.0.1
    fallback-enabled: no
    for-downstream: yes
    for-upstream: no
```

`for-downstream: yes` answers clients from the zone, and
`fallback-enabled: no` keeps Unbound from resolving the zone's names
elsewhere when the transfer fails. A zone created in Bindizr later needs its
own `auth-zone:` block, and a deleted one its block removed.

Unbound serves `test.` and the other special-use names of RFC 6761 as local
zones, which shadow an `auth-zone` of the same name. Add
`local-zone: "test." nodefault` under `server:` for such a zone.

## 3. Check a zone

```bash
dig +norec @127.0.0.1 example.com SOA
```

An authoritative answer carrying Bindizr's serial means the zone loaded.

## Changes arrive on the SOA refresh

In the verified setup Unbound refused every NOTIFY, Bindizr's and a hand-sent
one alike, even from an `allow-notify` address. Changes therefore arrive when
Unbound next checks the zone's SOA, after `dns.zone_defaults.refresh`
(300 seconds by default), and then as an IXFR delta. Lower the zone's
`refresh` where that wait is too long.

## Transfers are unsigned

Unbound has no TSIG for `auth-zone` transfers, so the registered address is
what authorizes it.
