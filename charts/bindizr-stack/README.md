# bindizr-stack

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

Create or reference a TSIG Secret:

```sh
kubectl create secret generic bindizr-tsig \
  --from-literal=rndc-key='BASE64_TSIG_SECRET'
```

Install:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.image.repository=ghcr.io/your-org/bindizr \
  --set bindizr.database.existingSecret=bindizr-db-secret \
  --set tsig.existingSecret=bindizr-tsig
```

For local testing, the chart can create Secrets from values:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.serverUrl='postgresql://user:password@postgresql:5432/bindizr' \
  --set tsig.secret='BASE64_TSIG_SECRET'
```

To run a bundled MySQL database for development:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.type=mysql \
  --set bindizr.database.existingSecret= \
  --set mysql.enabled=true \
  --set tsig.secret='BASE64_TSIG_SECRET'
```

To run SQLite for local testing without an external database:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.type=sqlite \
  --set bindizr.replicas=1 \
  --set tsig.secret='BASE64_TSIG_SECRET'
```

## Notes

- External MySQL/PostgreSQL is supported through `bindizr.database.existingSecret` or `bindizr.database.serverUrl`.
- SQLite can use a chart-managed PVC or `emptyDir` through `bindizr.database.sqlite.persistence`.
- Bundled Bitnami MySQL/PostgreSQL charts are optional and controlled by `mysql.enabled` and `postgresql.enabled`.
