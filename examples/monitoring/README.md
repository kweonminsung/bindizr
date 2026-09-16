# Monitoring Example

Prometheus + Grafana stack for bindizr's `GET /metrics`, with a pre-provisioned
**Bindizr Overview** dashboard (zone/record gauges, HTTP rate and p95 latency,
XFR/NOTIFY/nsupdate rates).

Start bindizr with the API on port 3000 and `api.listen_addr = "0.0.0.0"`
(on Linux, containers cannot reach a host listener bound to `127.0.0.1`), then:

```bash
$ docker compose up -d
```

- Prometheus: http://localhost:9090 (scrapes every 5 s; rules at http://localhost:9090/alerts)
- Grafana: http://localhost:3001 (anonymous viewer; log in as `admin`/`admin` to edit)

The scrape target defaults to `host.docker.internal:3000` (bindizr on the
Docker host); edit [prometheus.yml](prometheus.yml) for other setups. Full
metric reference: [Prometheus Metrics](../../docs/http-api/metrics.md).

[alerts.yml](alerts.yml) carries rules for the failures worth paging on:
bindizr unreachable, expired or lagging DNSSEC signatures, a failing
scheduler pass, NOTIFY and transfer failures, unpruned history, 5xx rate, and
a thrashing transfer cache. It has no Alertmanager attached, so the rules
show under **Alerts** rather than notifying; point Prometheus at your own
Alertmanager to route them.