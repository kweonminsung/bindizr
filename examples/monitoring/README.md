# Monitoring Example

Prometheus + Grafana stack for bindizr's `GET /metrics`, with a pre-provisioned
**Bindizr Overview** dashboard (zone/record gauges, HTTP rate and p95 latency,
XFR/NOTIFY/nsupdate rates).

Start bindizr with the API on port 3000, then:

```bash
$ docker compose up -d
```

- Prometheus: http://localhost:9090 (scrapes every 5 s)
- Grafana: http://localhost:3001 (anonymous admin)

The scrape target defaults to `host.docker.internal:3000` (bindizr on the
Docker host); edit [prometheus.yml](prometheus.yml) for other setups. Full
metric reference: [Prometheus Metrics](../../README.md#prometheus-metrics).