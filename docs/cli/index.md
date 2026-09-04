# CLI Commands

Bindizr provides a command-line interface for managing the DNS synchronization
service, its zone data, access control (API tokens, TSIG keys), and DNSSEC.
`bindizr help` lists everything; this page covers the commands you reach for
most and points to the pages that cover the rest.

Every command except `start` and `config check` talks to the running daemon
over its Unix socket, which is owner-only because connecting grants full
control. Run the CLI as the user the daemon runs as: `sudo bindizr ...` for a
package install, or a shell inside the container for Compose and Helm.

## Command map

Each global object is followed by its per-zone counterpart; the per-zone
commands take the zone name as their first argument.

| Commands | What they manage | Documented in |
|---|---|---|
| `start`, `stop`, `restart`, `status`, `doctor`, `config` | The daemon and its configuration | this page |
| `zone`, `record` | Zone data: CRUD, import/export, versions, NOTIFY, secondary status | this page |
| `token`, `token-policy` | API tokens and the zones each may change over HTTP | [API Tokens](tokens.md) |
| `tsig-key`, `tsig-policy` | TSIG keys and the zones each may update with nsupdate | [TSIG Keys](tsig-keys.md), [Dynamic Updates](nsupdate.md) |
| `dnssec-policy`, `dnssec` | Signing-parameter bundles and each zone's signing state | [DNSSEC](../dnssec.md) |

Every `create`, `list`, `get`, and `update` command prints a table and takes
`-o json` or `-o yaml`; `delete` and the one-shot actions print a message.
`zone export`, `dnssec ds`, and `dnssec keys export` print paste-ready text.

## Service

```bash
# Start bindizr on foreground
$ bindizr start

# Start with a custom configuration file
$ bindizr start -c <FILE>

# Stop the running daemon, or restart it in place
$ bindizr stop
$ bindizr restart

# Check the current status of bindizr service
$ bindizr status

# Verify the installation end to end (config, daemon, API, database, DNS, secondaries)
$ bindizr doctor

# Validate a configuration file without starting bindizr (defaults to /etc/bindizr/bindizr.conf.toml)
$ bindizr config check [<FILE>]

# Show the configuration loaded by the running daemon, or one value by dotted key
$ bindizr config list
$ bindizr config get dns.secondary_addrs
```

## Zones and records

```bash
# Create a zone (the SOA serial starts at 1 unless --serial is given)
$ bindizr zone create --name example.com --mname ns1.example.com --rname admin@example.com --default-ttl 3600

# List, inspect, and delete zones
$ bindizr zone list
$ bindizr zone get example.com
$ bindizr zone delete example.com

# Update a zone, changing only the fields you pass
$ bindizr zone update <ZONE_NAME> --refresh 300 --retry 60

# Create, list, inspect, and delete records (TTL defaults to the zone's)
$ bindizr record create --zone example.com --name www --type A --value 192.0.2.1 --ttl 300
$ bindizr record list --zone example.com
$ bindizr record get <RECORD_ID>
$ bindizr record delete <RECORD_ID>

# Update a record, changing only the fields you pass
$ bindizr record update <RECORD_ID> --value 127.0.0.1

# Export a zone as BIND master-file text (--signed appends the derived DNSSEC records)
$ bindizr zone export example.com > db.example.com

# Send NOTIFY to secondary DNS servers for a zone
$ bindizr zone notify <ZONE_NAME>

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
transfer):

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
