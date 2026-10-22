# Migrating from an Existing Primary

Move zones by importing them over AXFR, verifying the records, then pointing
the secondaries at Bindizr. Keep the old primary serving during verification.
For signed zones, complete the [DNSSEC preparation](#zones-with-dnssec)
before switching secondaries.

## 1. Let Bindizr transfer from the old primary

Bindizr pulls with an ordinary AXFR, so the old primary has to allow the
transfer from Bindizr's address. In BIND that is an `allow-transfer` entry on
the zone, or in its `options`:

```text
zone "example.com" {
    // ... whatever it already has ...
    allow-transfer { 192.0.2.10; };   // bindizr's address
};
```

Check it from the Bindizr host before going further:

```bash
dig @<old-primary> example.com AXFR | head
```

## 2. Import the zone, dry run first

`--create` builds the zone from the transferred SOA — its primary name server,
contact, timers, and **serial** — so the zone does not have to exist first.
Carrying the serial over matters: a secondary that already holds the old
primary's higher serial would ignore a zone that started from 1.

The source serial may be any value from **0 to 4,294,967,295**. Applying
record changes advances the carried-over serial once modulo 2^32, skipping
zero (RFC 2136, Section 7.11): `2026091601` becomes `2026091602`, and
`4294967295` becomes `1`.

`--from-server` pulls over AXFR instead of reading a file, and `--mode
replace` makes the zone match the source exactly. `--dry-run` reports what
would change and writes nothing, not even the zone:

```bash
bindizr zone import example.com --from-server <old-primary>:53 --mode replace --create --dry-run
bindizr zone import example.com --from-server <old-primary>:53 --mode replace --create
```

A zone file or AXFR can carry types Bindizr does not implement. An unsupported
user record rejects the whole import, leaving records and serial unchanged.
Review the supported types before moving a zone; there is no option to skip
unsupported records.

To choose your own SOA fields, create the zone first and import without
`--create`. Choose an initial serial consistent with the old primary:

```bash
bindizr zone create example.com --mname ns1.example.com --rname admin@example.com --serial 2026091601
bindizr zone import example.com --from-server <old-primary>:53 --mode replace
```

### Moving every zone in one run

The same import takes a whole server at once. Name the zones in a file, one
per line, as the old primary spells them; blank lines and `#` comments are
skipped. The primary's own tooling writes that list:

```bash
named-checkconf -l | awk '$2 == "IN" && $3 == "primary" { print $1 }' > zones.txt   # BIND
knotc zone-status | awk -F'[][]' '{ print $2 }' > zones.txt                           # Knot DNS
pdnsutil list-all-zones > zones.txt                                                   # PowerDNS

bindizr zone import --from-server <old-primary>:53 --zones zones.txt --mode replace --create --dry-run
bindizr zone import --from-server <old-primary>:53 --zones zones.txt --mode replace --create
```

A primary that already publishes a catalog zone (RFC 9432) needs no list:
`--from-catalog` transfers the catalog and imports every member it names.
The catalog transfer must be allowed from Bindizr's address like any other.

```bash
bindizr zone import --from-server <old-primary>:53 --from-catalog catalog.example --mode replace --create
```

Every zone is imported on its own, so a zone that is rejected (a record
Bindizr cannot store) or fails (the transfer refused, the zone missing)
leaves the rest imported; the table reports each zone's result, and the
command exits non-zero when any was left behind. Fix those and run the same
command again: a zone already moved replaces itself with no change. Over
HTTP the same is `POST /import`.

## 3. Compare before cutting over

Export what Bindizr now serves and diff it against the source:

```bash
dig @<old-primary> example.com AXFR +noall +answer > /tmp/old.zone
bindizr zone export example.com > /tmp/new.zone
diff <(sort /tmp/old.zone) <(sort /tmp/new.zone)
```

Text differences can include SOA values, name formatting, and TXT escaping.
Compare names, types, TTLs, and values, and review any records reported as
skipped. Repeat the import after stopping writes to the old primary so changes
made during verification are included in the cutover.

## 4. Point the secondaries at Bindizr

Only now do the secondaries change. Each one drops its old `zone` statements
and takes Bindizr's catalog zone instead, after which created and deleted
zones reach it without further configuration.
[Secondary Servers](../secondaries/index.md) has the configuration for each
verified server; use `<bindizr-host>` port 5300 in place of the
loopback address there, then restart the secondary.

Then confirm every secondary is serving Bindizr's serial:

```bash
bindizr zone status example.com
bindizr doctor
```

Keep the old primary available until all secondaries report Bindizr's serial
and answer the expected records. If you need to switch back, reconcile any
changes made in Bindizr and ensure the old primary's serial is newer than
the serial the secondaries currently serve.

## Zones with DNSSEC

Import the user records first. A signed AXFR also carries generated DNSSEC
records, which are managed separately and omitted from the user-record import.
Use `--dry-run` to review the result. Before switching secondaries, choose one of these paths:

- **Re-sign with Bindizr's own keys.** `bindizr dnssec enable example.com
  --parent-ns-addrs <parent name servers>` generates fresh keys, and the
  parent's DS must be coordinated with the change of signer. Do not switch
  secondaries while the parent trusts only the old keys; account for cached
  DS records as well.
- **Keep the existing keys.** Import them in BIND's `K*.key` / `K*.private`
  form with `bindizr dnssec keys import` under a matching policy. Verify the
  DS and signed responses before cutover; retaining the trusted keys avoids
  changing the parent's DS.

[DNSSEC](../dnssec/index.md) covers both, including what the parent must publish and
when.
