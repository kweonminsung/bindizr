# CLI Commands

Bindizr provides a command-line interface for managing the DNS synchronization
service, its zone data, and API tokens. `bindizr help` lists everything;
this page covers the commands you reach for most.

## Service

```bash
# Start bindizr on foreground
$ bindizr start

# Start with a custom configuration file
$ bindizr start -c <FILE>

# Check the current status of bindizr service
$ bindizr status

# Verify the installation end to end (config, daemon, API, database, DNS, secondaries)
$ bindizr doctor

# Validate a configuration file without starting bindizr (defaults to /etc/bindizr/bindizr.conf.toml)
$ bindizr config check [<FILE>]

# Show the configuration loaded by the running daemon
$ bindizr config list
```

## Zones and records

```bash
# Send NOTIFY to secondary DNS servers for a zone
$ bindizr zone notify <ZONE_NAME>

# Update a zone, changing only the fields you pass
$ bindizr zone update <ZONE_NAME> --refresh 300 --retry 60

# Update a record, changing only the fields you pass
$ bindizr record update <RECORD_ID> --value 127.0.0.1

# Check how far each secondary has caught up with a zone
$ bindizr zone status <ZONE_NAME>
```

Bulk changes can be previewed before anything is written. `--preview` renders
the change as a `+`/`-`/`~` diff and applies nothing:

```bash
$ bindizr record bulk-create records.json --zone <ZONE_NAME> --preview
$ bindizr zone import <ZONE_NAME> zone.txt --preview
```

A zone served elsewhere imports without exporting a file first —
`--from-server` pulls the records over AXFR (the source must allow the
transfer; its SOA and DNSSEC records are dropped since the zone keeps its
own SOA fields and signs itself):

```bash
$ bindizr zone import <ZONE_NAME> --from-server 192.0.2.1:53 --mode replace --preview
```

## Zone history

Every SOA serial has a version behind it, so a zone can be diffed and rolled
back.

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

A rollback restores the records captured at that serial but still advances the
serial forward, so secondaries see it as an ordinary change and pick it up over
IXFR.
