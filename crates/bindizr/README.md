# Bindizr

`bindizr` is a Rust-based DNS control plane for managing BIND9-backed zones and records.
It provides an HTTP API, a CLI, database-backed storage, and DNS zone transfer support for
secondary DNS servers.

## Features

- Manage DNS zones and records through an HTTP API or CLI.
- Store state in MySQL, PostgreSQL, or SQLite.
- Serve AXFR and IXFR zone transfers to secondary DNS servers.
- Publish DNS Catalog Zones (RFC 9432) for automatic BIND9 secondary configuration.
- Send DNS NOTIFY messages after zone changes.
- Support RFC 2136 dynamic updates with TSIG keys and per-zone grants.
- Sign zones with DNSSEC: key lifecycle, NSEC and NSEC3 denial, scheduled
  re-signing, and key rollover.
- Scope API tokens to individual zones, optionally by record-name pattern and type.
- Keep a version per SOA serial: list, diff, and roll a zone back.
- Import and export BIND master-file text, and bulk-insert records.
- Act as an ExternalDNS webhook provider for Kubernetes.
- Expose Prometheus metrics and an OpenAPI document.

## Installation

Install the CLI from crates.io:

```bash
cargo install bindizr
```

## Quick Start

Create a configuration file at `/etc/bindizr/bindizr.conf.toml`:

```toml
[api]
listen_addr = "127.0.0.1"     # HTTP API listen address
listen_port = 3000            # HTTP API listen port
require_authentication = true # Enable API authentication (true/false)
metrics_enabled = true        # Serve Prometheus metrics at GET /metrics (unauthenticated, aggregate counts only)
external_dns_enabled = false  # Register the ExternalDNS provider API at /external-dns
openapi_enabled = false       # Serve the OpenAPI document at GET /openapi.json and /openapi.yaml (unauthenticated)

[database]
type = "mysql"                # Database type: mysql, sqlite, postgresql

[database.mysql]
server_url = "mysql://user:password@hostname:port/database" # Mysql server configuration

[database.sqlite]
file_path = "bindizr.db"      # SQLite database file path

[database.postgresql]
server_url = "postgresql://user:password@hostname:port/database" # PostgreSQL server configuration

[dns]
listen_addr = "127.0.0.1"     # DNS server listen address
listen_port = 53              # DNS server listen port (UDP and TCP)
secondary_addrs = ""          # Comma-separated secondary DNS server addresses for NOTIFY (e.g., "192.168.1.2:53,192.168.1.3:53") 
notify_after_update = true    # Send DNS NOTIFY after zone changes
notify_mode = "sync"          # "sync": NOTIFY runs inline; "async": queued to a background worker
notify_batch_ms = 50          # async only: window to batch NOTIFYs into one per zone (0 disables the wait)
zone_cache = true             # Cache each zone's records by serial so repeated AXFRs skip the DB read
notify_on_startup = false     # Send DNS NOTIFY when bindizr starts
notify_retries = 3            # Retry count after the initial NOTIFY attempt
notify_timeout_secs = 3       # Timeout in seconds for each NOTIFY send/response wait
nsupdate_allow_unsigned = false # Accept unsigned nsupdate requests (not recommended in production; TSIG keys/grants are managed via CLI or HTTP API)
journal_retention_days = 365  # Days of IXFR journal/SOA history to keep (0 = unlimited); bounds rollback depth, pruned serials fall back to AXFR

[dnssec]
signature_validity_days = 14  # RRSIG validity period
signature_refresh_days = 5    # Re-sign when a signature has fewer than this many days left (must be < validity)
rollover_publish_holddown_secs = 86400 # Wait before a pre-published key may start signing (ZSKs auto-advance)
rollover_retire_holddown_secs = 172800 # Wait before a retired key is removed from the zone

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
```

Start bindizr:

```bash
bindizr start --config /etc/bindizr/bindizr.conf.toml
```

Use the CLI to inspect and manage resources:

```bash
bindizr status
bindizr token create --name admin --global
bindizr zone create --name example.com --mname ns1.example.com --rname admin@example.com --default-ttl 3600
bindizr zone list
bindizr zone import example.com db.example.com --mode upsert
bindizr zone version list example.com
bindizr zone version diff example.com 7
bindizr zone version rollback example.com 7 --dry-run
bindizr dnssec enable example.com
bindizr token grant ci example.com --types A,AAAA
bindizr zone status example.com
bindizr record list --zone example.com
bindizr record bulk-create records.json --zone example.com
bindizr zone notify example.com
```

## Packages

This workspace is split into several crates:

- `bindizr`: CLI, HTTP API, DNS server, daemon socket, and application entry point.
- `bindizr-core`: shared configuration, models, logging, and the DNS library
  (record types, wire format, DNSSEC signing, TSIG, zone files).
- `bindizr-db`: database repositories and schema helpers.
- `bindizr-service`: zone, record, token, serial, DNSSEC, and notification workflows.
- `bindizr-external-dns`: the ExternalDNS webhook provider adapter, shipped as a
  second binary.

## Documentation

- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr>
- License: Apache-2.0
