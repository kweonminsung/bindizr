# Prometheus Metrics

When `api.metrics_enabled` is on (the default), bindizr serves Prometheus
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
| `bindizr_zones_total`, `bindizr_records_total` | gauge | Zone / record counts, refreshed at scrape time |
| `bindizr_http_requests_total{method, route, status}` | counter | HTTP API requests, labeled by route pattern |
| `bindizr_http_request_duration_seconds{method, route}` | histogram | HTTP API request latency |
| `bindizr_xfr_total{type, result}` | counter | AXFR/IXFR requests served, by query type and outcome |
| `bindizr_notify_sent_total{result}` | counter | NOTIFY delivery attempts to secondaries, by outcome |
| `bindizr_nsupdate_requests_total{result}` | counter | RFC 2136 dynamic updates, by outcome |
| `bindizr_zone_serial_bumps_total` | counter | Zone serial writes across every update path |

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
