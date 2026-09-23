# PowerDNS

Catalog zones need **PowerDNS Authoritative 4.7 or newer**; Bindizr's
interoperability run covers 4.9.

## 1. Register the secondary in Bindizr

Bindizr sends NOTIFY to, and accepts unsigned transfers from, only the
entries of `dns.secondary_addrs`; a PowerDNS missing from it gets every
transfer refused. The packaged default, `127.0.0.1:53`, covers a PowerDNS on
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

PowerDNS signs only the catalog transfer (see
[below](#tsig-does-not-reach-member-zones)), so the list is what authorizes
its member transfers.

## 2. Configure the catalog zone

A consumer zone is an ordinary secondary zone whose kind says it carries a
catalog, so it is created with `pdnsutil` rather than written into a file.
Enable secondary operation in `/etc/powerdns/pdns.conf` first:

```text
secondary=yes
allow-notify-from=127.0.0.1
```

```bash
$ sudo pdnsutil create-secondary-zone catalog.bindizr 127.0.0.1:5300
$ sudo pdnsutil set-kind catalog.bindizr consumer
$ sudo systemctl restart pdns
```

PowerDNS creates each member zone with the catalog's primary, so nothing
further is needed for the zones themselves.

## 3. Check a zone it learned

```bash
$ sudo pdnsutil list-member-zones catalog.bindizr
example.com
```

## Transfers are AXFR, not IXFR

PowerDNS pulls member zones with a full transfer unless a zone is explicitly
told to ask for an incremental one. Bindizr serves both, so this costs
bandwidth on large or frequently-changed zones but changes nothing about what
PowerDNS ends up serving.

## Propagation takes about a second

PowerDNS acts on a NOTIFY when its secondary communicator next runs, measured
at roughly 1s p50 from write to visible against 12ms for Knot.
`xfr-cycle-interval` sets only how often zones are polled *without* a NOTIFY,
and there is no sub-second setting for the communicator, so this is a property
to plan around rather than tune.

## TSIG does not reach member zones

A TSIG key attaches to a PowerDNS zone through that zone's
`AXFR-MASTER-TSIG` metadata:

```bash
$ sudo pdnsutil import-tsig-key xfr-key hmac-sha256 "<base64 secret>"
$ sudo pdnsutil activate-tsig-key catalog.bindizr xfr-key secondary
```

That signs the **catalog** transfer only. PowerDNS creates the member zones
without copying the metadata, so every member transfer goes out unsigned.
Setting it by hand on a member zone works —

```bash
$ sudo pdnsutil set-meta example.com AXFR-MASTER-TSIG xfr-key
```

— but those zones appear on their own as the catalog grows, so there is no
point at which to do it.

**With PowerDNS, treat `dns.secondary_addrs` as the only thing authorizing a
member transfer.** Bindizr logs each transfer with `signed=true` or
`signed=false`, so the difference is visible:

```text
XFR TCP query: zone="catalog.bindizr", qtype=Rtype::AXFR, from=10.0.0.14, signed=true
XFR TCP query: zone="example.com",     qtype=Rtype::AXFR, from=10.0.0.14, signed=false
```

BIND, Knot, and NSD all reuse the catalog's key for member transfers; this is
specific to PowerDNS.
