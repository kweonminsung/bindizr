# bindizr-chart

Deploys Bindizr as a DB-backed DNS control plane with BIND9 authoritative DNS pods.

```text
CLI / HTTP / nsupdate
        |
        v
Bindizr(DB-backed Control Plane)
        |
        | AXFR / IXFR / NOTIFY
        v
BIND9 Secondary Pods
        |
        v
Kubernetes
```

## Install

Create or reference a database Secret:

```sh
kubectl create secret generic bindizr-db-secret \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'
```

Install the released OCI chart from Docker Hub:

```sh
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.5 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

The examples below install from the local chart source instead.

For local testing, the chart can create Secrets from values:

```sh
helm install bindizr ./charts \
  --set bindizr.database.serverUrl='postgresql://user:password@postgresql:5432/bindizr'
```

To run a bundled MySQL database for development:

```sh
helm install bindizr ./charts \
  --set bindizr.database.type=mysql \
  --set bindizr.database.existingSecret= \
  --set mysql.enabled=true
```

To run a bundled PostgreSQL database for development:

```sh
helm install bindizr ./charts \
  --set bindizr.database.type=postgresql \
  --set bindizr.database.existingSecret= \
  --set postgresql.enabled=true
```

To enable bindizr-ui:

```sh
helm install bindizr ./charts \
  --set bindizrUi.enabled=true
```

## Notes

- External MySQL/PostgreSQL is supported through `bindizr.database.existingSecret` or `bindizr.database.serverUrl`.
- SQLite is not supported by this Helm chart.
- nsupdate TSIG keys and per-zone policies are managed at runtime (`bindizr tsig-key`, `bindizr zone tsig-policy`, or the HTTP API), not through Helm values; `bindizr.dns.nsupdateAllowUnsigned` (default `false`) accepts unsigned updates and is not recommended in production.
- BIND9 accepts NOTIFY from any source by default through `allow-notify { any; }`.
- Bundled MySQL/PostgreSQL are optional single-replica StatefulSets using the configured Docker images and controlled by `mysql.enabled` and `postgresql.enabled`.
