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

Optionally create or reference a TSIG Secret for nsupdate authentication:

```sh
kubectl create secret generic bindizr-tsig \
  --from-literal=nsupdate-key='BASE64_TSIG_SECRET'
```

Install:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

For local testing, the chart can create Secrets from values:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.serverUrl='postgresql://user:password@postgresql:5432/bindizr'
```

To run a bundled MySQL database for development:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.type=mysql \
  --set bindizr.database.existingSecret= \
  --set mysql.enabled=true
```

To run a bundled PostgreSQL database for development:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizr.database.type=postgresql \
  --set bindizr.database.existingSecret= \
  --set postgresql.enabled=true
```

To enable bindizr-ui:

```sh
helm install bindizr ./charts/bindizr-stack \
  --set bindizrUi.enabled=true
```

## Notes

- External MySQL/PostgreSQL is supported through `bindizr.database.existingSecret` or `bindizr.database.serverUrl`.
- SQLite is not supported by this Helm chart.
- TSIG is optional. Set `tsig.existingSecret` or `tsig.secret` only when nsupdate TSIG authentication is needed.
- BIND9 accepts NOTIFY from any source by default through `allow-notify { any; }`.
- Bundled MySQL/PostgreSQL are optional single-replica StatefulSets using the configured Docker images and controlled by `mysql.enabled` and `postgresql.enabled`.
