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

| Commands | What they manage | Documented in |
|---|---|---|
| `start`, `stop`, `restart`, `status`, `doctor`, `config` | The daemon and its configuration | this page |
| `zone`, `record`, `notify` | Zone data: CRUD, import/export, versions, NOTIFY, secondary status | this page |
| `token` | API tokens and the zones each is granted over HTTP | [API Tokens](tokens.md) |
| `tsig-key` | TSIG keys and the zones each is granted for nsupdate | [TSIG Keys](tsig-keys.md), [Dynamic Updates](nsupdate.md) |
| `dnssec-policy`, `dnssec` | Signing-parameter bundles and each zone's signing state | [DNSSEC](../dnssec.md) |

Every `create`, `list`, `get`, and `update` command prints a table and takes
`-o json` or `-o yaml`, whose payload is the same body the HTTP API returns;
`delete` and the one-shot actions print a message.
`zone export` and `dnssec keys export` print paste-ready text.

## Service

```bash
# Start bindizr on foreground
$ bindizr start

# Start with a custom configuration file. `start`, `doctor`, and `config check`
# all take `-c` and fall back to $BINDIZR_CONFIG_PATH
$ bindizr start -c <FILE>

# Stop the running daemon, or restart it in place
$ bindizr stop
$ bindizr restart

# Whether the daemon runs, where it listens, its database and zone count, and its secondaries
$ bindizr status

# Check the installation end to end; without a daemon it checks the database, the
# listen ports, and BIND's catalog setup itself
$ bindizr doctor

# Validate a configuration file without starting bindizr (defaults to /etc/bindizr/bindizr.conf.toml)
$ bindizr config check [-c <FILE>]

# Show the configuration loaded by the running daemon, or one value by dotted key
$ bindizr config list
$ bindizr config get dns.secondary_addrs

# Re-read the configuration file without restarting (`systemctl reload bindizr` or SIGHUP does the same)
$ bindizr config reload

# doctor also answers as one JSON document, for a cron job or CI check
$ bindizr doctor -o json
```

## Completions and the man page

A package install puts both in place already. Elsewhere the binary prints
them, generated from the same command it parses with:

```bash
# Shell completion: bash, zsh, fish, elvish, or powershell
$ bindizr completion bash | sudo tee /usr/share/bash-completion/completions/bindizr
$ bindizr completion zsh  | sudo tee /usr/share/zsh/site-functions/_bindizr
$ bindizr completion fish > ~/.config/fish/completions/bindizr.fish

# Man page
$ bindizr man | sudo tee /usr/share/man/man1/bindizr.1 > /dev/null
```

## Zones and records

```bash
# Create a zone (--rname defaults to hostmaster@<zone>; the SOA serial starts at 1
# unless --serial is given; --refresh, --retry, --expire, and --minimum-ttl set the other SOA timers)
$ bindizr zone create example.com --mname ns1.example.com --default-ttl 3600

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
$ bindizr record create --zone example.com --name www --type A --value 192.0.2.1 --ttl 300
$ bindizr record create --zone example.com --name @ --type TXT --value v=spf1 --value ~all  # repeat --value for TXT segments
$ bindizr record list --zone example.com
$ bindizr record list --zone example.com --sort ttl --order desc
$ bindizr zone list --min-serial 100 --signed --sort created_at
$ bindizr record get <RECORD_ID>
$ bindizr record delete <RECORD_ID>

# Update a record, changing only the fields you pass
$ bindizr record update <RECORD_ID> --value 127.0.0.1

# Export a zone as BIND master-file text (--signed appends the derived DNSSEC records)
$ bindizr zone export example.com > db.example.com

# Send NOTIFY to secondary DNS servers for a zone, or for every zone
$ bindizr zone notify <ZONE_NAME>
$ bindizr notify

# Check how far each secondary has caught up with a zone
$ bindizr zone status <ZONE_NAME>

# List the API token and TSIG key grants that apply to a zone
$ bindizr zone token-grants <ZONE_NAME>
$ bindizr zone tsig-grants <ZONE_NAME>
```

Bulk changes can be previewed before anything is written. `--dry-run` applies
nothing and renders the change as a `+`/`-`/`~` diff:

```bash
$ bindizr record bulk-create records.json --zone <ZONE_NAME> --dry-run
$ bindizr zone import <ZONE_NAME> zone.txt --dry-run
```

A zone served elsewhere imports without exporting a file first —
`--from-server` pulls the records over AXFR (the source must allow the
transfer); [Migrating an Existing Primary](../deployment/migrating.md) walks
through a whole cutover:

```bash
$ bindizr zone import <ZONE_NAME> --from-server 192.0.2.1:53 --mode replace --dry-run
```

A zone file written for BIND often carries record types bindizr does not
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
it was made under (`system` for the DNSSEC maintenance scheduler, `local` for
the daemon socket or a request made while authentication is disabled). The
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

## Exit codes

A failure exits with the class of the error, so a script can branch on it
without parsing the message.

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Failure, including invalid input |
| `2` | Usage error, such as an unknown command or a missing argument |
| `3` | Not found: no such zone, record, token, version, key, or policy |
| `4` | Conflict: the name is taken, or the object is in use or in the wrong state |
| `5` | Denied: the token is missing, invalid, or lacks a grant |
| `6` | Unavailable: the daemon is not running, so the command never reached it |
