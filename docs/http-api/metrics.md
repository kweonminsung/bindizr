# Prometheus Metrics

When `api.metrics_enabled` is on (the default), Bindizr serves Prometheus
text-format metrics at `GET /metrics`. Like `/health`, the endpoint is
unauthenticated — it exposes only aggregate counters and gauges, never zone data
— and it is not part of the OpenAPI spec.

```bash
curl http://localhost:3000/metrics
```

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `bindizr_build_info{version}` | gauge | Build metadata; the value is always 1 |
| `bindizr_started_at_seconds` | gauge | Unix time the process started |
| `bindizr_database_up` | gauge | Whether this scrape's database probe succeeded (3 s timeout) |
| `bindizr_db_connections{state}` | gauge | Pooled database connections by state (`idle`/`in_use`); `in_use` reaching the max is the saturation every request then queues behind |
| `bindizr_db_connections_max` | gauge | Connection ceiling the pool was built with, scaled to the host's cores |
| `bindizr_zones_total`, `bindizr_records_total` | gauge | Zone / record counts, refreshed at scrape time |
| `bindizr_http_requests_total{method, route, status}` | counter | HTTP API requests, labeled by route pattern |
| `bindizr_http_request_duration_seconds{method, route}` | histogram | HTTP API request latency |
| `bindizr_xfr_total{kind, result, transport}` | counter | AXFR/IXFR requests, by kind, result, and transport (`udp`, `tcp`, `tls`). A UDP AXFR or an IXFR that needs a stream retry counts as `truncated`. When the IXFR client's serial is equal or newer and UDP returns the current SOA in full, it counts as `ok`. |
| `bindizr_soa_queries_total{result}` | counter | SOA queries answered, by outcome. An answer sent with TC set and no SOA counts as `truncated`. Secondaries poll these on their refresh timer, so a rise in `refused` can signal an ACL mismatch. |
| `bindizr_notify_sent_total{result}` | counter | NOTIFY send attempts to secondaries, by outcome |
| `bindizr_nsupdate_requests_total{result}` | counter | nsupdate requests (RFC 2136), by outcome |
| `bindizr_pruned_rows_total{table}` | counter | Rows pruned from `zone_journal`, `zone_versions`, `activity_log`, `access_log`, or `transfer_log`. Zero is expected until rows exceed the retention period. |
| `bindizr_access_log_dropped_total` | counter | Access log rows dropped unsaved because the write queue was full; the requests were answered, only their rows are missing. Nonzero means a burst outran the database |
| `bindizr_zone_serial_bumps_total` | counter | Committed zone serial writes across every update path |
| `bindizr_dnssec_zones_total` | gauge | DNSSEC-signed zones, refreshed at scrape time |
| `bindizr_dnssec_keys_total{state}` | gauge | DNSSEC keys by state (`published`/`active`/`retired`) |
| `bindizr_dnssec_rrsigs_expiring_total` | gauge | Signatures inside the refresh window; persisting across scrapes means re-signing is falling behind |
| `bindizr_dnssec_rrsigs_expired_total` | gauge | Signatures already past their expiration; any at all mean resolvers are failing part of a zone |
| `bindizr_dnssec_scheduler_runs_total{result}` | counter | DNSSEC scheduler passes by outcome; interval set by `dns.scheduler_interval_secs` |
| `bindizr_zone_cache_lookups_total{result}` | counter | Transfer-cache reads by outcome; a low hit ratio means transfers reach the database anyway |
| `bindizr_zone_cache_evictions_total` | counter | Zones dropped to make room; rising beside a low hit ratio means `dns.transfer.cache_max_records` is too small |
| `bindizr_zone_cache_records` | gauge | Records the transfer cache holds, against `dns.transfer.cache_max_records` |

Example Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: bindizr
    static_configs:
      - targets: ["localhost:3000"]
```

Set `metrics_enabled = false` in the `[api]` section (or
`BINDIZR_API_METRICS_ENABLED=false`) to disable the endpoint.

A ready-to-run Prometheus + Grafana stack with a pre-provisioned dashboard lives
in [examples/monitoring/](https://github.com/kweonminsung/bindizr/tree/main/examples/monitoring).
