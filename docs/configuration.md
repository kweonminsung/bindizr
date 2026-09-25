# Configuration

Bindizr reads configuration from `/etc/bindizr/bindizr.conf.toml`, and every
option can also be set with an environment variable. Container deployments use
the environment form; the Compose files and the Helm chart in this repository set the same
options that way.

The file path can be overridden with `-c <FILE>` on `start`, `doctor`, and
`config check`, or with the `BINDIZR_CONFIG_PATH` environment variable.
Environment variables are applied **after** the file is parsed, so they win
over anything the file sets.

```bash
$ bindizr config check            # validate a file without starting
$ bindizr config list             # show what the running daemon loaded
$ bindizr config reload           # re-read the file in the running daemon
```

## Reloading

`bindizr config reload`, `systemctl reload bindizr`, or `SIGHUP` to the
daemon re-reads the file and applies it without a restart. What a running process cannot adopt is refused
**whole** — the file is not partly applied — so the running configuration
always describes the running process:

| | |
| --- | --- |
| Reloadable | the whole `[dns]` section and `[logging]` |
| Fixed while running | the `[api]` and `[database]` sections, `dns.listen_addr`, `dns.listen_port`, `dns.catalog_zone_name` |

A reload names the sections it changed; a refusal names the settings that
would need a restart and leaves the running configuration alone.

## Configuration file

For manual installation, create the configuration file and adjust the values to
match your environment. Commented-out keys show their default and can be left
out; a key Bindizr does not know is an error, so `config check` catches a typo.

```toml title="/etc/bindizr/bindizr.conf.toml"
[api]
listen_addr = "127.0.0.1"
listen_port = 3000
authentication_required = true # Require an API token; `bindizr token create` makes the first one
metrics_enabled = true        # Prometheus metrics at /metrics (unauthenticated)
external_dns_enabled = false  # ExternalDNS provider API at /external-dns
openapi_enabled = false       # OpenAPI document at /openapi.json and /openapi.yaml (unauthenticated)
# tls_cert_file = "/etc/bindizr/tls/tls.crt"  # Set both to serve HTTPS; without them the HTTP API is
# tls_key_file = "/etc/bindizr/tls/tls.key"   # unencrypted and its tokens travel in the clear

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
# catalog_zone_name = "catalog.bindizr"  # The RFC 9432 catalog zone secondaries follow. A secondary
                              # holds one zone per name, so two primaries feeding one secondary need
                              # two names. Fixed while bindizr runs.
nsupdate_tsig_required = true  # RFC 2136 updates must be TSIG-signed; false admits anyone
# zone_history_retention_days = 365 # Days of history kept for rollback and secondary catch-up (0 = forever)
# scheduler_interval_secs = 3600    # Seconds between background passes: signing, key rollover, history pruning

[dns.notify]                  # NOTIFY to the secondaries
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
level = "info"                # error, warn, info, debug, trace
# format = "text"             # text, or json for one object per line
```

A reserved character in the user, password, or database of a database `url`
(`#`, `@`, `:`, `/`, `?`, a space) is percent-encoded, `p@ss` as `p%40ss`;
Bindizr decodes the components before connecting. The Helm chart encodes
the credentials it assembles from the bundled database's `auth` values.

Whether a zone is signed, and the signing parameters it uses, are not
configuration: enable DNSSEC per zone under a DNSSEC policy managed through
the HTTP API or CLI — see [DNSSEC](dnssec/index.md).

## Environment variables

A variable is `BINDIZR_` plus the key's path in upper case with `_` for `.`:
`dns.notify.batch_ms` is `BINDIZR_DNS_NOTIFY_BATCH_MS`.

| Variable | Sets | Notes |
| --- | --- | --- |
| `BINDIZR_CONFIG_PATH` | configuration file path | Falls back to `/etc/bindizr/bindizr.conf.toml` |
| `BINDIZR_API_LISTEN_ADDR` | `api.listen_addr` | |
| `BINDIZR_API_LISTEN_PORT` | `api.listen_port` | |
| `BINDIZR_API_AUTHENTICATION_REQUIRED` | `api.authentication_required` | |
| `BINDIZR_API_METRICS_ENABLED` | `api.metrics_enabled` | |
| `BINDIZR_API_EXTERNAL_DNS_ENABLED` | `api.external_dns_enabled` | See [ExternalDNS](external-dns.md) |
| `BINDIZR_API_OPENAPI_ENABLED` | `api.openapi_enabled` | Describes the whole API surface; off by default |
| `BINDIZR_API_TLS_CERT_FILE` | `api.tls_cert_file` | Empty clears it |
| `BINDIZR_API_TLS_KEY_FILE` | `api.tls_key_file` | Empty clears it |
| `BINDIZR_DATABASE_TYPE` | `database.type` | `mysql`, `postgresql`, or `sqlite` |
| `BINDIZR_DATABASE_URL` | the URL for the selected backend | Ignored when the type is `sqlite` |
| `BINDIZR_DATABASE_MYSQL_URL` | `database.mysql.url` | |
| `BINDIZR_DATABASE_POSTGRESQL_URL` | `database.postgresql.url` | |
| `BINDIZR_DATABASE_SQLITE_FILE_PATH` | `database.sqlite.file_path` | |
| `BINDIZR_DNS_LISTEN_ADDR` | `dns.listen_addr` | |
| `BINDIZR_DNS_LISTEN_PORT` | `dns.listen_port` | |
| `BINDIZR_DNS_CATALOG_ZONE_NAME` | `dns.catalog_zone_name` | every secondary names the same zone in its own configuration |
| `BINDIZR_DNS_NSUPDATE_TSIG_REQUIRED` | `dns.nsupdate_tsig_required` | `false` is testing only; see [Dynamic Updates](cli/nsupdate.md#unsigned-requests) |
| `BINDIZR_DNS_ZONE_HISTORY_RETENTION_DAYS` | `dns.zone_history_retention_days` | `0` keeps history forever |
| `BINDIZR_DNS_SCHEDULER_INTERVAL_SECS` | `dns.scheduler_interval_secs` | `0` runs no scheduler pass on this instance |
| `BINDIZR_DNS_NOTIFY_BATCH_MS` | `dns.notify.batch_ms` | see [Batching NOTIFY](#batching-notify) |
| `BINDIZR_DNS_NOTIFY_RETRIES` | `dns.notify.retries` | |
| `BINDIZR_DNS_NOTIFY_TIMEOUT_SECS` | `dns.notify.timeout_secs` | |
| `BINDIZR_DNS_TRANSFER_CACHE_ENABLED` | `dns.transfer_cache.enabled` | |
| `BINDIZR_DNS_TRANSFER_CACHE_MAX_RECORDS` | `dns.transfer_cache.max_records` | see [Sizing the transfer cache](#sizing-the-transfer-cache) |
| `BINDIZR_DNS_ZONE_DEFAULTS_TTL` | `dns.zone_defaults.ttl` | answers an omitted `default_ttl` on zone creation |
| `BINDIZR_DNS_ZONE_DEFAULTS_REFRESH` | `dns.zone_defaults.refresh` | |
| `BINDIZR_DNS_ZONE_DEFAULTS_RETRY` | `dns.zone_defaults.retry` | |
| `BINDIZR_DNS_ZONE_DEFAULTS_EXPIRE` | `dns.zone_defaults.expire` | |
| `BINDIZR_DNS_ZONE_DEFAULTS_MINIMUM_TTL` | `dns.zone_defaults.minimum_ttl` | |
| `BINDIZR_LOGGING_LEVEL` | `logging.level` | |
| `BINDIZR_LOGGING_FORMAT` | `logging.format` | `text` or `json` |

`BINDIZR_DATABASE_URL` is a convenience for container deployments where the URL
arrives from one secret regardless of backend: it writes to whichever
backend `BINDIZR_DATABASE_TYPE` selected.

## Secondaries

The secondaries are not in this file. They are registered at runtime with
`bindizr secondary create` or `POST /secondaries`, stored beside the zones,
and take effect on the next NOTIFY or transfer — see
[Secondaries](cli/secondaries.md).

## Batching NOTIFY

`dns.notify.batch_ms` decides what happens on the write path once a change is
committed.

`0` (the default)
:   Every change sends its own NOTIFY before the write is answered. Lowest
    latency to visibility.

a window in milliseconds
:   The write is answered at commit; changes to the same zone inside the
    window collapse into one NOTIFY, sent from a queue. Worth it when many
    records change at once.

## Sizing the transfer cache

`dns.transfer_cache.max_records` counts records, not bytes, so converting a
memory budget takes one step. A cached record costs roughly:

| Record | Cost |
| --- | --- |
| `A` with a short name | 130 bytes |
| `TXT` with a 255-byte value | 375 bytes |
| `TXT` carrying a DKIM key | 860 bytes |

The default of 500,000 records is about 64 MiB of plain address records, more
where large `TXT` values or a signed zone's derived records dominate. Watch
`bindizr_zone_cache_records` against the limit and
`bindizr_zone_cache_evictions_total`: evictions rising beside a low hit ratio in
`bindizr_zone_cache_lookups_total` mean the working set does not fit.
