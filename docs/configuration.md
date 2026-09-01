# Configuration

Bindizr reads configuration from `/etc/bindizr/bindizr.conf.toml`, and every
option can also be set with an environment variable. Container deployments use
the environment form; the Docker and Helm files in this repository set the same
options that way.

The file path can be overridden with `bindizr start -c <FILE>` or the
`BINDIZR_CONFIG_PATH` environment variable. Environment variables are applied
**after** the file is parsed, so they win over anything the file sets.

```bash
$ bindizr config check            # validate a file without starting
$ bindizr config list             # show what the running daemon loaded
```

## Configuration file

For manual installation, create the configuration file and adjust the values to
match your environment:

```toml title="/etc/bindizr/bindizr.conf.toml"
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
nsupdate_allow_unsigned = false # Accept unsigned nsupdate requests (not recommended in production; TSIG keys/policies are managed via CLI or HTTP API)
journal_retention_days = 365  # Days of IXFR journal/SOA history to keep (0 = unlimited); bounds rollback depth, pruned serials fall back to AXFR

[dnssec]
default_signature_validity_days = 14  # RRSIG validity period
default_signature_refresh_days = 5    # Re-sign when a signature has fewer than this many days left (must be < validity)
rollover_publish_holddown_secs = 86400 # Wait before a pre-published key may start signing (ZSKs auto-advance)
rollover_retire_holddown_secs = 172800 # Wait before a retired key is removed from the zone
default_zsk_lifetime_days = 0         # Roll ZSKs active longer than this automatically (0 = disabled)
parent_ds_resolver = ""        # Resolver (host[:port]) asked for the parent DS before ds-seen; empty skips the check
parent_ds_auto_promote = false          # Poll the resolver for pending DS records and promote CSK/KSK rollovers unattended
# The three default_*_days knobs are per-zone-overridable via `bindizr zone dnssec timing`.

[logging]
log_level = "debug"           # Log level: error, warn, info, debug, trace
```

Whether a zone is signed is not configuration: enable DNSSEC per zone through
the API or CLI — see [DNSSEC](dnssec.md).

## Environment variables

| Variable | Sets | Notes |
| --- | --- | --- |
| `BINDIZR_CONFIG_PATH` | config file path | Falls back to `/etc/bindizr/bindizr.conf.toml` |
| `BINDIZR_API_LISTEN_ADDR` | `api.listen_addr` | |
| `BINDIZR_API_PORT` | `api.listen_port` | |
| `BINDIZR_API_REQUIRE_AUTHENTICATION` | `api.require_authentication` | |
| `BINDIZR_API_METRICS_ENABLED` | `api.metrics_enabled` | |
| `BINDIZR_API_EXTERNAL_DNS_ENABLED` | `api.external_dns_enabled` | See [ExternalDNS](external-dns.md) |
| `BINDIZR_API_OPENAPI_ENABLED` | `api.openapi_enabled` | Describes the whole API surface; off by default |
| `BINDIZR_DATABASE_TYPE` | `database.type` | `mysql`, `postgresql`, or `sqlite` |
| `BINDIZR_DATABASE_URL` | the URL for the selected backend | Ignored when the type is `sqlite` |
| `BINDIZR_MYSQL_SERVER_URL` | `database.mysql.server_url` | |
| `BINDIZR_POSTGRESQL_SERVER_URL` | `database.postgresql.server_url` | |
| `BINDIZR_SQLITE_FILE_PATH` | `database.sqlite.file_path` | |
| `BINDIZR_DNS_LISTEN_ADDR` | `dns.listen_addr` | |
| `BINDIZR_DNS_PORT` | `dns.listen_port` | |
| `BINDIZR_SECONDARY_ADDRS` | `dns.secondary_addrs` | |
| `BINDIZR_NOTIFY_AFTER_UPDATE` | `dns.notify_after_update` | |
| `BINDIZR_NOTIFY_ON_STARTUP` | `dns.notify_on_startup` | |
| `BINDIZR_NOTIFY_RETRIES` | `dns.notify_retries` | |
| `BINDIZR_NOTIFY_TIMEOUT_SECS` | `dns.notify_timeout_secs` | |
| `BINDIZR_NOTIFY_MODE` | `dns.notify_mode` | `sync` or `async` |
| `BINDIZR_NOTIFY_BATCH_MS` | `dns.notify_batch_ms` | `async` mode only |
| `BINDIZR_ZONE_CACHE` | `dns.zone_cache` | |
| `BINDIZR_NSUPDATE_ALLOW_UNSIGNED` | `dns.nsupdate_allow_unsigned` | |
| `BINDIZR_JOURNAL_RETENTION_DAYS` | `dns.journal_retention_days` | `0` keeps history forever |
| `BINDIZR_DNSSEC_DEFAULT_SIGNATURE_VALIDITY_DAYS` | `dnssec.default_signature_validity_days` | |
| `BINDIZR_DNSSEC_DEFAULT_SIGNATURE_REFRESH_DAYS` | `dnssec.default_signature_refresh_days` | |
| `BINDIZR_DNSSEC_ROLLOVER_PUBLISH_HOLDDOWN_SECS` | `dnssec.rollover_publish_holddown_secs` | |
| `BINDIZR_DNSSEC_ROLLOVER_RETIRE_HOLDDOWN_SECS` | `dnssec.rollover_retire_holddown_secs` | |
| `BINDIZR_DNSSEC_DEFAULT_ZSK_LIFETIME_DAYS` | `dnssec.default_zsk_lifetime_days` | |
| `BINDIZR_DNSSEC_PARENT_DS_RESOLVER` | `dnssec.parent_ds_resolver` | |
| `BINDIZR_DNSSEC_PARENT_DS_AUTO_PROMOTE` | `dnssec.parent_ds_auto_promote` | Needs `parent_ds_resolver`; see [DNSSEC](dnssec.md) |
| `BINDIZR_LOG_LEVEL` | `logging.log_level` | |

`BINDIZR_DATABASE_URL` is a convenience for container deployments where the URL
arrives from one secret regardless of backend: it writes to whichever
backend `BINDIZR_DATABASE_TYPE` selected.

## Notify mode

`notify_mode` controls what happens on the write path once a change is committed.

`sync`
:   The zone reload and NOTIFY run inline, so the API call does not return until
    secondaries have been notified. Lowest latency to visibility, and the
    default.

`async`
:   The change is committed and the reload/NOTIFY is queued to a background
    worker. Writes return sooner, and `notify_batch_ms` collapses NOTIFYs for the
    same zone into one per window — worth it when many records change at once.
