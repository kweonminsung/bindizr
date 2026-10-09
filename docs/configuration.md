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
bindizr config check            # validate a file without starting
bindizr config list             # show what the running daemon loaded
bindizr config reload           # re-read the file in the running daemon
```

## Reloading

Use `bindizr config reload`, `systemctl reload bindizr`, or `SIGHUP` to apply
reloadable settings. If any fixed setting changes, the entire reload is
rejected and the current configuration stays active.

| Settings | Reload behavior |
| --- | --- |
| `[logging]` and `[dns]` except the settings below | Reloadable |
| `[api]`, `[database]`, `[dns.tls]`, `dns.listen_addr`, `dns.listen_port`, `dns.catalog_zone_name`, `dns.tcp_max_connections` | Restart required |
| The certificate and key files `[api.tls]` and `[dns.tls]` name | Re-read on reload, so a renewed pair serves without a restart; the paths stay fixed |

A reload names the sections it changed; a refusal names the settings that
would need a restart and leaves the running configuration alone.

## Configuration file

Packages install this configuration file. For other installations, create it
and adjust the values. Commented settings are optional; unknown keys are
rejected by `config check`.

```toml title="/etc/bindizr/bindizr.conf.toml"
[api]
listen_addr = "127.0.0.1"
listen_port = 3000
authentication_required = true # Require an API token; `bindizr token create` makes the first one
metrics_enabled = true        # Prometheus metrics at /metrics (unauthenticated)
external_dns_enabled = false  # ExternalDNS provider API at /external-dns
openapi_enabled = false       # OpenAPI document at /openapi.json and /openapi.yaml (unauthenticated)

[api.tls]                     # Set both files to serve HTTPS
# cert_file = "/etc/bindizr/tls/tls.crt"
# key_file = "/etc/bindizr/tls/tls.key"

[database]
type = "sqlite"               # sqlite, mysql, or postgresql

[database.mysql]
url = "mysql://user:password@hostname:port/database"

[database.sqlite]
file_path = "/var/lib/bindizr/bindizr.db"

[database.postgresql]
url = "postgresql://user:password@hostname:port/database"

[database.tls]                # TLS to the MySQL or PostgreSQL server; unset leaves it to the URL
# mode = "verify-full"        # disable, prefer, require, verify-ca, verify-full
# ca_file = "/etc/bindizr/db-ca.crt"  # A private issuer; needs verify-ca or verify-full

[dns]
listen_addr = "127.0.0.1"
listen_port = 5300            # UDP and TCP; 53 is left to BIND on the same host
# catalog_zone_name = "catalog.bindizr"  # RFC 9432 catalog zone the secondaries follow; fixed while running
# zone_history_retention_days = 365      # Days of history for rollback and IXFR (0 = forever)
# scheduler_interval_secs = 3600         # Seconds between signing, rollover, and pruning passes
# tcp_idle_timeout_secs = 30             # Idle time between queries before a TCP or TLS connection closes; advertised as edns-tcp-keepalive (RFC 7828)
# tcp_max_connections = 128              # TCP and TLS connections served at once; the rest wait in the accept backlog

[dns.notify]                  # NOTIFY to the secondaries
# batch_ms = 0                # Window to batch a zone's NOTIFYs (0 = send before answering)
# retries = 3
# timeout_secs = 3            # Seconds to wait for each NOTIFY

[dns.nsupdate]                # RFC 2136 dynamic updates
tsig_required = true          # false admits unsigned updates from anyone

[dns.tls]                     # Set both files to serve zone transfers over TLS (XoT, RFC 9103)
# listen_port = 853           # On dns.listen_addr
# cert_file = "/etc/bindizr/tls/xot.crt"
# key_file = "/etc/bindizr/tls/xot.key"

[dns.transfer]                # Zone transfers
# cache_max_records = 500000  # Zone records cached per serial; a larger zone is served uncached (0 = no cache)
# require_tls = false         # Refuse AXFR/IXFR over plain TCP and UDP; needs [dns.tls], SOA queries still answer

[dns.import]                  # zone import --from-server: the AXFR Bindizr pulls
# timeout_secs = 30
# max_records = 200000        # A larger zone is refused

[dns.zone_defaults]           # Applied when a zone-creation request omits the field
ttl = 3600                    # Default record TTL (seconds)
refresh = 300                 # SOA refresh; NOTIFY drives propagation, this only bounds a lost one
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

`[database.tls]` is the connection to a MySQL or PostgreSQL server, which a
managed database usually requires over TLS. Without a `mode`, TLS is used
when the server offers it and the certificate is not checked; `require`
insists on TLS and checks nothing either. A server reached over a network
should be verified: `verify-full` checks the chain and the host name against
the system's roots, or against `ca_file` when the issuer is private, as the
certificate bundles of RDS and Cloud SQL are. The URL's own parameters
(`sslmode`, `ssl-mode`) still work; a set key overrides them, and `ca_file`
needs its verifying `mode` beside it rather than in the URL.

Use distinct catalog names for independent Bindizr deployments feeding the
same secondary. Configure [TLS](http-api/index.md#tls) before exposing the API
off-host. Signing settings are managed per zone through [DNSSEC](dnssec/index.md).

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
| `BINDIZR_API_TLS_CERT_FILE` | `api.tls.cert_file` | Empty clears it |
| `BINDIZR_API_TLS_KEY_FILE` | `api.tls.key_file` | Empty clears it |
| `BINDIZR_DATABASE_TYPE` | `database.type` | `mysql`, `postgresql`, or `sqlite` |
| `BINDIZR_DATABASE_URL` | the URL for the selected backend | Ignored when the type is `sqlite` |
| `BINDIZR_DATABASE_MYSQL_URL` | `database.mysql.url` | |
| `BINDIZR_DATABASE_POSTGRESQL_URL` | `database.postgresql.url` | |
| `BINDIZR_DATABASE_SQLITE_FILE_PATH` | `database.sqlite.file_path` | |
| `BINDIZR_DATABASE_TLS_MODE` | `database.tls.mode` | Empty leaves it to the URL |
| `BINDIZR_DATABASE_TLS_CA_FILE` | `database.tls.ca_file` | Empty clears it |
| `BINDIZR_DNS_LISTEN_ADDR` | `dns.listen_addr` | |
| `BINDIZR_DNS_LISTEN_PORT` | `dns.listen_port` | |
| `BINDIZR_DNS_CATALOG_ZONE_NAME` | `dns.catalog_zone_name` | every secondary names the same zone in its own configuration |
| `BINDIZR_DNS_NSUPDATE_TSIG_REQUIRED` | `dns.nsupdate.tsig_required` | `false` is testing only; see [Dynamic Updates](cli/nsupdate.md#unsigned-requests) |
| `BINDIZR_DNS_ZONE_HISTORY_RETENTION_DAYS` | `dns.zone_history_retention_days` | `0` keeps history forever |
| `BINDIZR_DNS_SCHEDULER_INTERVAL_SECS` | `dns.scheduler_interval_secs` | `0` runs no scheduler pass on this instance |
| `BINDIZR_DNS_NOTIFY_BATCH_MS` | `dns.notify.batch_ms` | see [Batching NOTIFY](configuration/advanced.md#batching-notify) |
| `BINDIZR_DNS_NOTIFY_RETRIES` | `dns.notify.retries` | |
| `BINDIZR_DNS_NOTIFY_TIMEOUT_SECS` | `dns.notify.timeout_secs` | |
| `BINDIZR_DNS_TLS_LISTEN_PORT` | `dns.tls.listen_port` | |
| `BINDIZR_DNS_TLS_CERT_FILE` | `dns.tls.cert_file` | Empty clears it |
| `BINDIZR_DNS_TLS_KEY_FILE` | `dns.tls.key_file` | Empty clears it |
| `BINDIZR_DNS_TRANSFER_CACHE_MAX_RECORDS` | `dns.transfer.cache_max_records` | `0` caches nothing; see [Sizing the transfer cache](configuration/advanced.md#sizing-the-transfer-cache) |
| `BINDIZR_DNS_TRANSFER_REQUIRE_TLS` | `dns.transfer.require_tls` | needs `[dns.tls]` |
| `BINDIZR_DNS_TCP_IDLE_TIMEOUT_SECS` | `dns.tcp_idle_timeout_secs` | 1 to 6553 |
| `BINDIZR_DNS_TCP_MAX_CONNECTIONS` | `dns.tcp_max_connections` | |
| `BINDIZR_DNS_IMPORT_TIMEOUT_SECS` | `dns.import.timeout_secs` | |
| `BINDIZR_DNS_IMPORT_MAX_RECORDS` | `dns.import.max_records` | |
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

When to batch NOTIFY and how to size the transfer cache is in
[Advanced Configuration](configuration/advanced.md).
