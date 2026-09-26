# Prometheus Metrics

When `api.metrics_enabled` is on (the default), Bindizr serves Prometheus
text-format metrics at `GET /metrics`. Like `/health`, the endpoint is
unauthenticated — it exposes only aggregate counters and gauges, never zone data
— and it is not part of the OpenAPI spec.

```bash
$ curl http://localhost:3000/metrics
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
| `bindizr_xfr_total{type, result}` | counter | AXFR/IXFR requests served, by query type and outcome; a UDP request counts as `truncated`, since the transfer itself follows over TCP |
| `bindizr_soa_queries_total{result}` | counter | SOA queries answered, by outcome; secondaries poll these on their refresh timer, so a rise in `refused` means one stopped being an enabled secondary |
| `bindizr_notify_sent_total{result}` | counter | NOTIFY delivery attempts to secondaries, by outcome |
| `bindizr_nsupdate_requests_total{result}` | counter | RFC 2136 dynamic updates, by outcome |
| `bindizr_pruned_rows_total{table}` | counter | Rows the retention pass deleted, by table (`journal`/`version`); a rate of zero while zones keep changing means the journal is growing without bound |
| `bindizr_zone_serial_bumps_total` | counter | Zone serial writes across every update path |
| `bindizr_dnssec_zones_total` | gauge | DNSSEC-signed zones, refreshed at scrape time |
| `bindizr_dnssec_keys_total{state}` | gauge | DNSSEC keys by state (`published`/`active`/`retired`) |
| `bindizr_dnssec_rrsigs_expiring_total` | gauge | Signatures inside the refresh window; persisting across scrapes means re-signing is falling behind |
| `bindizr_dnssec_rrsigs_expired_total` | gauge | Signatures already past their expiration; any at all mean resolvers are failing part of a zone |
| `bindizr_dnssec_scheduler_runs_total{result}` | counter | Hourly DNSSEC scheduler passes, by outcome |
| `bindizr_zone_cache_lookups_total{result}` | counter | Transfer-cache reads by outcome; a low hit ratio means transfers reach the database anyway |
| `bindizr_zone_cache_evictions_total` | counter | Zones dropped to make room; rising beside a low hit ratio means `dns.transfer_cache.max_records` is too small |
| `bindizr_zone_cache_records` | gauge | Records the transfer cache holds, against `dns.transfer_cache.max_records` |

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
