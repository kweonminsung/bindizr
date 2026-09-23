# NSD

Catalog zones need **NSD 4.9 or newer**; Bindizr's interoperability run covers
4.12.

## 1. Register the secondary in Bindizr

Bindizr sends NOTIFY to, and accepts unsigned transfers from, only the
entries of `dns.secondary_addrs`; an NSD missing from it gets every
transfer refused. The packaged default, `127.0.0.1:53`, covers an NSD on
the same host. One elsewhere is added by address or hostname — see
[Configuration](../configuration.md#secondaries) — and the list reloads
without a restart:

```toml title="/etc/bindizr/bindizr.conf.toml"
[dns]
secondary_addrs = "10.0.0.14:53"
```

```bash
$ sudo bindizr config reload
```

A [signed transfer](#sign-the-transfers) is authorized by its key, but NOTIFY
still goes only to the list, so a keyed secondary is listed all the same.

## 2. Configure the catalog zone

`catalog: consumer` marks the zone, and `catalog-member-pattern` names the
pattern every member zone is created with — so the pattern, not the catalog
zone, carries the primary those zones transfer from. Add this to
`/etc/nsd/nsd.conf`:

```text
pattern:
    name: "catalog-member"
    zonefile: "members/%s.zone"
    allow-notify: 127.0.0.1 NOKEY
    request-xfr: 127.0.0.1@5300 NOKEY

zone:
    name: "catalog.bindizr"
    zonefile: "catalog.bindizr.zone"
    catalog: consumer
    catalog-member-pattern: "catalog-member"
    allow-notify: 127.0.0.1 NOKEY
    request-xfr: 127.0.0.1@5300 NOKEY
```

NSD writes each member's zone file itself, but not the directory holding them.
`zonefile:` is relative to `zonesdir`, which differs by distribution, so ask
NSD where it is:

```bash
$ sudo install -d -o nsd -g nsd "$(nsd-checkconf -o zonesdir /etc/nsd/nsd.conf)/members"
$ sudo nsd-checkconf /etc/nsd/nsd.conf
$ sudo systemctl restart nsd
```

## 3. Check a zone it learned

`zonestatus` reports the catalog member id the zone was provisioned under:

```bash
$ sudo nsd-control zonestatus example.com
zone:	example.com
	pattern: catalog-member
	catalog-member-id: 33220188aa7541b8d3b935bd11880c49.zones.catalog.bindizr.
	state: ok
	served-serial: "12 since 2026-01-01T00:00:00"
```

## Two defaults worth knowing

NSD holds a received transfer for up to `xfrd-reload-timeout` seconds — one by
default — before the serving process picks it up, so a change takes about a
second to become visible even though the transfer finished in milliseconds.
Reloading as each transfer lands costs CPU in proportion to how often zones
change, so it is a trade rather than a fix:

```text
server:
    xfrd-reload-timeout: 0
```

NSD also discards the deltas it receives unless told to keep them, and answers
an inbound IXFR with a full transfer. This matters only where something pulls
zones *from* NSD, such as a downstream secondary:

```text
pattern:
    name: "catalog-member"
    store-ixfr: yes
```

Bindizr's [benchmark suite](https://github.com/kweonminsung/bindizr/tree/main/benchmarks)
measures both: 1050ms versus 6.7ms p50 visibility, and 700 bytes versus 55KB
for a single-record change on a 1000-record zone.

## Sign the transfers

Declare the key, then name it in place of `NOKEY` on `request-xfr` — in the
pattern as well as the catalog zone, so member transfers are signed too:

```text
key:
    name: "xfr-key"
    algorithm: hmac-sha256
    secret: "<base64 secret from bindizr tsig-key create --global>"

pattern:
    name: "catalog-member"
    zonefile: "members/%s.zone"
    allow-notify: 10.0.0.5 NOKEY
    request-xfr: 10.0.0.5@5300 xfr-key

zone:
    name: "catalog.bindizr"
    zonefile: "catalog.bindizr.zone"
    catalog: consumer
    catalog-member-pattern: "catalog-member"
    allow-notify: 10.0.0.5 NOKEY
    request-xfr: 10.0.0.5@5300 xfr-key
```

The catalog zone takes the key too: it is the transfer every member is
provisioned from, so leaving it on `NOKEY` signs everything except the one
that has to arrive first.

`allow-notify` stays `NOKEY`: Bindizr sends NOTIFY unsigned, so requiring the
key there would reject it.

See [TSIG Keys](../cli/tsig-keys.md) for creating the key and granting it the
zones it may transfer.
