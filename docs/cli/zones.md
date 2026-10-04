# Zones and Records

Use `bindizr zone` and `bindizr record` to manage zones, records, imports,
and history. Run the CLI on the daemon host as its user or root; see
[CLI Commands](index.md). Commands that report results support `-o json`
and `-o yaml`; `zone export` writes zone-file text instead.

## Create a zone

```bash
bindizr zone create example.com --mname ns1.example.com --rname admin@example.com --default-ttl 3600
bindizr zone list
bindizr zone get example.com
```

`--mname` and `--rname` are required. The zone starts at serial 1 unless
`--serial` is given, and includes an apex `NS` record naming `--mname`.
Use `--no-apex-ns` to supply the NS records yourself.

Add any other name servers and address records for names inside the zone.
Public delegation also needs matching glue at the parent for those names:

```bash
bindizr record create example.com @ --type NS --value ns2.example.com
bindizr record create example.com ns1 --type A --value 192.0.2.1
bindizr record create example.com ns2 --type A --value 192.0.2.2
```

## Add and update records

```bash
bindizr record create example.com www --type A --value 192.0.2.1 --ttl 300
bindizr record create example.com @ --type TXT --value "v=spf1 include:_spf.example.net ~all"
bindizr record list example.com
bindizr record get example.com www
bindizr record update example.com www --value 192.0.2.2
```

TTL defaults to the zone's TTL. Records sharing a name and type must share
one TTL. `record get` returns all records at a name; `record update` by name
requires exactly one. Use an ID from `record list` to select a specific record:

```bash
bindizr record get --id 42
bindizr record update --id 42 --value 192.0.2.2
```

Use `--new-name` to rename a record. A TXT value over 255 bytes is split into
segments automatically; repeat `--value` to choose the segments yourself.
Resolvers join them without inserting spaces.

## Filter records and change zone settings

```bash
bindizr record list example.com --sort ttl --order desc
bindizr zone list --min-serial 100 --signed --sort created_at
bindizr zone update example.com --refresh 300 --retry 60
```

Updates change only the fields you pass. A disabled zone keeps its editable
records but leaves the catalog and stops serving transfers, so secondaries
remove it:

```bash
bindizr zone update example.com --enabled false --description "paused for migration"
bindizr zone list --enabled false
bindizr zone update example.com --enabled true
```

## Export, NOTIFY, and secondary status

```bash
# Export BIND master-file text; --signed includes generated DNSSEC records
bindizr zone export example.com > db.example.com

# Send NOTIFY for one zone, or for all zones
bindizr zone notify example.com
bindizr zone notify

# Compare each secondary's serial with Bindizr's
bindizr zone status example.com
```

## Import and bulk changes

For bulk creation, save an array of records as `records.json`:

```json title="records.json"
[
  {"name": "api", "type": "A", "value": "192.0.2.3", "ttl": 300}
]
```

Preview bulk changes or an import with `--dry-run`; the `+`/`-`/`~` diff
shows additions, deletions, and updates without applying them:

```bash
bindizr record bulk-create example.com records.json --dry-run
bindizr zone import example.com db.example.com --mode replace --dry-run
```

Choose an import mode explicitly when replacing existing data:

| Mode | Effect |
| --- | --- |
| `append` (default) | Add records without replacing existing records |
| `upsert` | Replace records at the names and types present in the input |
| `replace` | Make the zone's records match the input, removing records absent from it |

`--from-server` imports over AXFR instead of reading a file. With `--create`,
a missing zone is created from the source SOA, preserving its timers and
serial. See [Migrating an Existing Primary](../deployment/migrating.md).

```bash
bindizr zone import example.com --from-server 192.0.2.1:53 --mode replace --create --dry-run
```

Validation errors reject the whole import. `--skip-unsupported` skips record
types Bindizr does not store and reports each one; review that list before
applying. Zone-file TTLs must be decimal seconds. Convert BIND time units such
as `1h` with `named-compilezone -o zone.txt example.com source.zone` first.

Over HTTP, `POST /zones/{name}/import` accepts either `content` (zone-file text)
or `from_server`, with the same `mode`, `dry_run`, and `skip_unsupported` options.

## Zone history

Each serial has a saved version. Rollback restores its records and SOA fields
while advancing the serial, so secondaries receive the change:

```bash
bindizr zone version list example.com
bindizr zone version diff example.com <FROM_SERIAL> [<TO_SERIAL>]
bindizr zone version get example.com <SERIAL>
bindizr zone version rollback example.com <SERIAL> --dry-run
```

Omit `TO_SERIAL` to compare with the current version. Versions record
`change_source` (`api`, `socket`, `nsupdate`, or `system`) and `changed_by`
(the API token or TSIG key's kind and name). That identity survives credential
deletion. CLI commands, unauthenticated requests, and background work have no
named credential, shown as `null` in JSON and `-` in a table.

## Delete records or a zone

Preview deletion first, then omit `--dry-run` to apply it:

```bash
bindizr record delete example.com www --type A --dry-run
bindizr record delete --id 42 --dry-run
bindizr zone delete example.com --dry-run
```

Deleting by name without `--type` removes every type at that name; use
`--type` and `--value` together to select one value. Deleting a zone removes
its records and saved versions as well.
