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

## Notes

- BIND9 is deployed as a StatefulSet with at least one replica so transferred zone files, journals, cache, and working directories can be stable per pod.
- `bindizr.dns.secondary_addrs` is rendered from BIND9 StatefulSet pod DNS names so Bindizr can send NOTIFY to each secondary replica.
- The Bitnami PostgreSQL chart is optional and controlled by `postgresql.enabled`.
