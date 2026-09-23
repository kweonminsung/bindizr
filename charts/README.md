# bindizr-chart

Deploys Bindizr as a DB-backed DNS control plane with BIND authoritative DNS pods.

```text
CLI / HTTP / nsupdate
        |
        v
Bindizr(DB-backed Control Plane)
        |
        | AXFR / IXFR / NOTIFY
        v
BIND9 Secondary Pods
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
  --version 0.1.0-rc.1 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

The examples below install from the local chart source instead.

For local testing, the chart can create Secrets from values:

```sh
helm install bindizr ./charts \
  --set bindizr.database.url='postgresql://user:password@postgresql:5432/bindizr'
```

To run a bundled PostgreSQL database for development:

```sh
helm install bindizr ./charts --set postgresql.enabled=true
```

Or a bundled MySQL, which also switches the database type:

```sh
helm install bindizr ./charts \
  --set bindizr.database.type=mysql \
  --set mysql.enabled=true
```

To enable bindizr-ui:

```sh
helm install bindizr ./charts \
  --set bindizrUi.enabled=true
```

To try the chart in a local kind cluster, see [`examples/kind/`](../examples/kind/).

## Notes

- Bindizr and BIND do not call the Kubernetes API, so the chart creates no Role or RoleBinding.
- `bind9.service.type` is `LoadBalancer`. Where nothing provisions one — kind, bare metal without MetalLB — set it to `NodePort`, with `bind9.service.nodePort` to pin the port.
- The secondaries live in Bindizr's database: a starting bindizr pod registers the BIND pods by their headless names, plus `bindizr.dns.extraSecondaries` (`name` and `address` each), through `bindizr secondary create`. Every daemon option has a value under `bindizr.*`, rendered into the ConfigMap.
- Non-secret daemon settings come from the ConfigMap; the database URL comes from its Secret through `BINDIZR_DATABASE_URL`.
- SQLite is not supported by this Helm chart.
- nsupdate TSIG keys and their zone grants are managed at runtime: `POST /tsig-keys` with a token, or `bindizr tsig-key` in the pod. `bindizr.dns.nsupdateTsigRequired` (default `true`) accepts unsigned updates when turned off, which is for testing only.
- BIND accepts NOTIFY from any source by default through `allow-notify { any; }`.
