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
  --version 0.1.0-beta.7 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

The examples below install from the local chart source instead.

For local testing, the chart can create Secrets from values:

```sh
helm install bindizr ./charts \
  --set bindizr.database.url='postgresql://user:password@postgresql:5432/bindizr'
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

- Bindizr and BIND9 do not call the Kubernetes API, so the chart creates no Role or RoleBinding.
- Non-secret daemon settings come from the ConfigMap; the database URL comes from its Secret through `BINDIZR_DATABASE_URL`.
- External MySQL/PostgreSQL is supported through `bindizr.database.existingSecret` or `bindizr.database.url`.
- SQLite is not supported by this Helm chart.
- The first API token can come from `bindizr.api.authentication.initialToken` (an existing Secret or a value), so no `kubectl exec` is needed; it is ignored once any token exists.
- nsupdate TSIG keys and their zone grants are managed at runtime (`bindizr tsig-key`, or the HTTP API); `bindizr.dns.nsupdate.initialKey` seeds the first one for a cluster that cannot run the CLI, and it is global. `bindizr.dns.nsupdate.tsigRequired` (default `true`) accepts unsigned updates when turned off, which is for testing only.
- BIND9 accepts NOTIFY from any source by default through `allow-notify { any; }`.
- Bundled MySQL/PostgreSQL are optional single-replica StatefulSets using the configured Docker images and controlled by `mysql.enabled` and `postgresql.enabled`.
