# Bindizr

`bindizr` is a Rust-based DNS control plane for BIND9, Knot DNS, NSD, and PowerDNS.
It provides an HTTP API, a CLI, database-backed storage, and DNS zone transfer support for
the secondary DNS servers, which discover zones through a catalog zone.

## Features

- Manage DNS zones and records through an HTTP API or CLI.
- Store state in MySQL, PostgreSQL, or SQLite.
- Serve AXFR and IXFR zone transfers to secondary DNS servers.
- Publish DNS Catalog Zones (RFC 9432) for automatic secondary configuration.
- Send DNS NOTIFY messages after zone changes.
- Support RFC 2136 dynamic updates with TSIG keys and per-zone grants.
- Sign zones with DNSSEC: key lifecycle, NSEC and NSEC3 denial, scheduled
  re-signing, key rollover, and a parent-DS check before going insecure.
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
listen_addr = "127.0.0.1"
listen_port = 3000
authentication_required = true # Require an API token; `bindizr token create` makes the first one
metrics_enabled = true        # Prometheus metrics at /metrics (unauthenticated)
external_dns_enabled = false  # ExternalDNS provider API at /external-dns
openapi_enabled = false       # OpenAPI document at /openapi.json and /openapi.yaml (unauthenticated)
# tls_cert_file = "/etc/bindizr/tls/tls.crt"  # Set both to serve HTTPS; without them the API is
# tls_key_file = "/etc/bindizr/tls/tls.key"   # plain HTTP and its tokens travel in the clear

[database]
type = "sqlite"               # sqlite, mysql, or postgresql

[database.mysql]
url = "mysql://user:password@hostname:port/database"

[database.sqlite]
file_path = "/var/lib/bindizr/bindizr.db"

[database.postgresql]
url = "postgresql://user:password@hostname:port/database"

[dns]
listen_addr = "127.0.0.1"
listen_port = 5300            # UDP and TCP; 53 is left to BIND on the same host
secondary_addrs = "127.0.0.1:53"  # Comma-separated; they receive NOTIFY and are the only clients
                              # allowed to pull zones. The default is a secondary on this host.
nsupdate_tsig_required = true  # RFC 2136 updates must be TSIG-signed; false admits anyone
# zone_history_retention_days = 365 # Days of history kept for rollback and secondary catch-up (0 = forever)
# scheduler_interval_secs = 3600    # Seconds between background passes: signing, key rollover, history pruning

[dns.notify]                  # NOTIFY to the secondaries
after_update = true           # Notify after zone changes
on_startup = false            # Notify for every zone at startup
# batch_ms = 0                # Window to batch a zone's NOTIFYs, sent after the write is answered (0 = before)
# retries = 3                 # Retries after the first attempt
# timeout_secs = 3            # Seconds to wait for each NOTIFY

[dns.transfer_cache]          # Zone records cached per serial, so repeated transfers skip the database
# enabled = true
# max_records = 500000        # Records the cache holds; a larger zone is served uncached

[dns.zone_defaults]           # Applied when a zone-creation request omits the field
ttl = 3600                    # Default record TTL (seconds)
refresh = 300                 # SOA refresh; NOTIFY drives propagation, so this only bounds a lost one
retry = 60                    # SOA retry
expire = 3600000              # SOA expire
minimum_ttl = 86400           # SOA minimum (negative-caching TTL)

[logging]
level = "debug"               # error, warn, info, debug, trace
# format = "text"             # text, or json for one object per line
```

Start bindizr:

```bash
bindizr start --config /etc/bindizr/bindizr.conf.toml
```

Use the CLI to inspect and manage resources:

```bash
bindizr status
bindizr token create admin --global
bindizr zone create example.com --mname ns1.example.com --rname admin@example.com --default-ttl 3600
bindizr zone list
bindizr zone import example.com db.example.com --mode upsert
bindizr zone version list example.com
bindizr zone version diff example.com 7
bindizr zone version rollback example.com 7 --dry-run
bindizr dnssec enable example.com --parent-ns-addrs a.gtld-servers.net
bindizr token grant ci example.com --types A,AAAA
bindizr zone status example.com
bindizr record list example.com
bindizr record bulk-create example.com records.json
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
