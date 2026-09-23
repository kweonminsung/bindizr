# Zones and Records

`bindizr zone` and `bindizr record` manage the zone data: create, inspect,
and change zones and records, import and export zone files, send NOTIFY,
and read each zone's history. Every command takes `-o json` or `-o yaml`
for the same payload the HTTP API returns.

## Create, inspect, and change

```bash
# Create a zone. --mname and --rname are both required: neither is guessed.
# The SOA serial starts at 1 unless --serial is given; --refresh, --retry,
# --expire, and --minimum-ttl set the other SOA timers
$ bindizr zone create example.com --mname ns1.example.com --rname admin@example.com --default-ttl 3600

# A new zone holds its SOA and nothing else. Give it the NS records that name
# its public name servers, and an address record for any of them inside the zone
# (the parent zone needs matching glue for those).
$ bindizr record create example.com @ --type NS --value ns1.example.com
$ bindizr record create example.com ns1 --type A --value 192.0.2.1

# List, inspect, and delete zones
$ bindizr zone list
$ bindizr zone get example.com
$ bindizr zone delete example.com

# Update a zone, changing only the fields you pass
$ bindizr zone update <ZONE_NAME> --refresh 300 --retry 60

# Stop serving a zone without deleting it: it leaves the catalog and answers no
# transfer, so secondaries drop it, while its records stay editable here
$ bindizr zone update example.com --enabled false --description "paused for migration"
$ bindizr zone list --enabled false
$ bindizr zone update example.com --enabled true

# Create, list, inspect, and delete records (TTL defaults to the zone's; one TTL per name and type)
$ bindizr record create example.com www --type A --value 192.0.2.1 --ttl 300
$ bindizr record create example.com @ --type TXT --value "v=spf1 include:_spf.example.net ~all"
$ bindizr record list example.com
$ bindizr record list example.com --sort ttl --order desc
$ bindizr zone list --min-serial 100 --signed --sort created_at
# A name can hold several records, so the name form answers with all of them
$ bindizr record get example.com www

# Delete by name: every type at the name, or narrowed by type and value
# (--dry-run reports what would go). The whole set moves in one serial.
$ bindizr record delete example.com www
$ bindizr record delete example.com www --type A --dry-run

# Update a record, changing only the fields you pass. Every flag sets a new
# value, so the name form needs the name to hold exactly one record.
$ bindizr record update example.com www --value 127.0.0.1
$ bindizr record update example.com www --new-name api

# --id addresses exactly one record, which is how a name holding several is
# narrowed down; `record list` prints the IDs.
$ bindizr record get --id 42
$ bindizr record update --id 42 --value 127.0.0.1
$ bindizr record delete --id 42
```

A TXT value over 255 bytes is split into segments for you. Repeat `--value` to
choose the split yourself, which is how a DKIM key is usually published.
Resolvers join the segments with nothing between them, so any space belongs
inside a value rather than between two of them.

## Export, NOTIFY, and secondary status
```bash
# Export a zone as BIND master-file text (--signed appends the derived DNSSEC records)
$ bindizr zone export example.com > db.example.com

# Send NOTIFY to secondary DNS servers for a zone, or for every zone
$ bindizr zone notify <ZONE_NAME>
$ bindizr zone notify              # every zone

# Check how far each secondary has caught up with a zone
$ bindizr zone status <ZONE_NAME>

# List the API token and TSIG key grants that apply to a zone
$ bindizr zone token-grants <ZONE_NAME>
$ bindizr zone tsig-grants <ZONE_NAME>
```

## Import and bulk changes

Bulk changes can be previewed before anything is written. `--dry-run` applies
nothing and renders the change as a `+`/`-`/`~` diff:

```bash
$ bindizr record bulk-create <ZONE_NAME> records.json --dry-run
$ bindizr zone import <ZONE_NAME> zone.txt --dry-run
```

A zone served elsewhere imports without exporting a file first —
`--from-server` pulls the records over AXFR (the source must allow the
transfer), and `--create` builds the zone from the file's SOA, carrying its
timers and serial, when it does not exist yet;
[Migrating an Existing Primary](../deployment/migrating.md) walks through a
whole cutover:

```bash
$ bindizr zone import <ZONE_NAME> --from-server 192.0.2.1:53 --mode replace --create --dry-run
```

A record that fails validation fails the whole import: nothing is applied, the
rejected records are listed on stderr, and the command exits non-zero so a CI
step does not read the rejection as success.

A zone file written for BIND often carries record types Bindizr does not
store, and one of them fails the whole import. `--skip-unsupported` passes
over those lines instead, reporting each one:

```bash
$ bindizr zone import <ZONE_NAME> zone.txt --skip-unsupported
```

Over HTTP, `POST /zones/{name}/import` takes either `content` (zone file
text) or `from_server` the same way, and `skip_unsupported` alongside them.

## Zone history

Every SOA serial has a version behind it, so a zone can be diffed and rolled
back, and each version records who made the change: the API token or TSIG key
it was made under (`system` for the DNSSEC scheduler, `local` for the CLI
or a request made while authentication is disabled). The
name is copied into the version, so it still answers after the token is gone.

```bash
# List a zone's versions (SOA serials are a plain counter starting at 1)
$ bindizr zone version list <ZONE_NAME>

# Diff the records between two serials (omit the second to compare to current)
$ bindizr zone version diff <ZONE_NAME> <FROM_SERIAL> [<TO_SERIAL>]

# Inspect the zone state captured at a serial
$ bindizr zone version get <ZONE_NAME> <SERIAL>

# Roll a zone back to a previous serial (the serial still advances)
$ bindizr zone version rollback <ZONE_NAME> <SERIAL> [--dry-run]
```
