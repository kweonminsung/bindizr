# Bindizr

`bindizr` is a Rust-based DNS control plane for managing BIND9-backed zones and records.
It provides an HTTP API, a CLI, database-backed storage, and DNS zone transfer support for
secondary DNS servers.

## Features

- Manage DNS zones and records through an HTTP API or CLI.
- Store state in MySQL, PostgreSQL, or SQLite.
- Serve AXFR and IXFR zone transfers to secondary DNS servers.
- Publish DNS Catalog Zones for automatic BIND9 secondary configuration.
- Send DNS NOTIFY messages after zone changes.
- Support RFC 2136-style dynamic updates with TSIG authentication.

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
notify_on_startup = false     # Send DNS NOTIFY when bindizr starts
notify_retries = 3            # Retry count after the initial NOTIFY attempt
notify_timeout_secs = 5       # Timeout in seconds for each NOTIFY send/response wait
nsupdate_tsig_key_name = "nsupdate-key" # TSIG key name for nsupdate authentication (name and key must both be set)
nsupdate_tsig_key = ""        # Shared TSIG secret for nsupdate authentication (name and key must both be set, base64 recommended)

[logging]
log_level = "info"           # Log level: error, warn, info, debug, trace
```

Start bindizr:

```bash
bindizr start --config /etc/bindizr/bindizr.conf.toml
```

Use the CLI to inspect and manage resources:

```bash
bindizr status
bindizr token create --description admin
bindizr create zone --name example.com --primary-ns ns1.example.com --admin-email admin.example.com --ttl 3600
bindizr get zones
bindizr get records --zone example.com
bindizr notify zone example.com
```

## Packages

This workspace is split into several crates:

- `bindizr`: CLI, HTTP API, daemon socket, and application entry point.
- `bindizr-core`: shared configuration, models, DNS record types, and logging.
- `bindizr-db`: database repositories and schema helpers.
- `bindizr-service`: zone, record, token, serial, and notification workflows.
- `bindizr-dns`: AXFR/IXFR, NOTIFY, TSIG, and nsupdate logic.

## Documentation

- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr>
- License: Apache-2.0
