# Migrating from an Existing Primary

Bindizr takes over as the primary for zones another nameserver serves today.
Nothing about the old server has to change until the last step, so each zone
can be moved and verified on its own.

The shape of the move: bindizr pulls each zone's records over a transfer, you
compare the result against the source, and only then do the secondaries start
answering from bindizr's catalog.

## 1. Let bindizr transfer from the old primary

Bindizr pulls with an ordinary AXFR, so the old primary has to allow the
transfer from bindizr's address. In BIND that is an `allow-transfer` entry on
the zone, or in its `options`:

```text
zone "example.com" {
    // ... whatever it already has ...
    allow-transfer { 192.0.2.10; };   // bindizr's address
};
```

Check it from the bindizr host before going further:

```bash
$ dig @<old-primary> example.com AXFR | head
```

## 2. Import the zone, dry run first

`--create` builds the zone from the transferred SOA — its primary nameserver,
contact, timers, and **serial** — so the zone does not have to exist first.
Carrying the serial over matters: a secondary that already holds the old
primary's higher serial would ignore a zone that started from 1.

`--from-server` pulls over AXFR instead of reading a file, and `--mode
replace` makes the zone match the source exactly. `--dry-run` reports what
would change and writes nothing, not even the zone:

```bash
$ bindizr zone import example.com --from-server <old-primary>:53 --mode replace --create --dry-run
$ bindizr zone import example.com --from-server <old-primary>:53 --mode replace --create
```

A zone file written for BIND often carries record types bindizr does not
store, and one of them fails the whole import. `--skip-unsupported` passes
over those lines and lists each one, so you can decide whether what it skipped
matters:

```bash
$ bindizr zone import example.com --from-server <old-primary>:53 --mode replace --create --skip-unsupported --dry-run
```

Where the source has no SOA to build from, or its fields are not what you want
to keep, create the zone yourself first and import without `--create`:

```bash
$ bindizr zone create example.com --mname ns1.example.com --serial 2026091601
$ bindizr zone import example.com --from-server <old-primary>:53 --mode replace
```

## 3. Compare before cutting over

Export what bindizr now serves and diff it against the source:

```bash
$ dig @<old-primary> example.com AXFR > /tmp/old.zone
$ bindizr zone export example.com > /tmp/new.zone
$ diff <(sort /tmp/old.zone) <(sort /tmp/new.zone)
```

Expect the SOA line and record ordering to differ. Anything else is a record
that did not survive the import.

## 4. Point the secondaries at bindizr

Only now do the secondaries change. Each one drops its old `zone` statements
and takes bindizr's catalog zone instead, after which created and deleted
zones reach it without further configuration — see
[Manual Installation](manual.md#3-configure-bind-as-secondary-with-catalog-zone)
for the BIND side, or run the bundled script:

```bash
$ sudo /usr/share/bindizr/setup_bind.sh <bindizr-host> 5300
$ sudo systemctl restart named
```

Then confirm every secondary is serving bindizr's serial:

```bash
$ bindizr zone status example.com
$ bindizr doctor
```

Leave the old primary running until the secondaries report bindizr's serial;
rolling back before that is only a matter of restoring their previous `zone`
statements.

## Zones with DNSSEC

Import the records first, then decide between two paths:

- **Re-sign with bindizr's own keys.** `bindizr dnssec enable example.com`
  generates fresh keys, and the parent's DS has to be replaced with the new
  one before the old keys stop being published.
- **Keep the existing keys.** Import them in BIND's `K*.key` / `K*.private`
  form with `bindizr dnssec keys import`, and the chain of trust at the parent
  stays valid across the move.

[DNSSEC](../dnssec.md) covers both, including what the parent must publish and
when.
