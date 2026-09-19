# Helm

Use the Helm chart to deploy Bindizr, BIND9 secondary pods, and optional bundled
MySQL/PostgreSQL in Kubernetes.

## Production: external database

Create a Kubernetes Secret that points Bindizr to your external MySQL or
PostgreSQL database:

```bash
$ kubectl create secret generic bindizr-db-secret \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'

$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

## Development: bundled database

For development, the chart can run a single-replica MySQL or PostgreSQL
StatefulSet:

```bash
$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.type=postgresql \
  --set bindizr.database.existingSecret= \
  --set postgresql.enabled=true
```

## The first credentials

Authentication is on by default, so the API answers `401` until a token exists.
The chart generates one at install and bindizr creates a global token with it
on the first start that finds none. The install notes print how to read it
back:

```bash
$ kubectl get secret bindizr-bindizr-chart-initial-token \
  -o jsonpath='{.data.api-token}' | base64 -d
```

Upgrades reuse the Secret, so the token survives them. To choose the token
yourself, hand the chart one at install:

```bash
$ kubectl create secret generic bindizr-initial-token --from-literal=api-token="$(openssl rand -hex 24)"

$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.existingSecret=bindizr-db-secret \
  --set bindizr.api.authentication.initialToken.existingSecret=bindizr-initial-token
```

Only the start that creates the schema reads it: pointing a release that
already serves at another Secret changes nothing, and a deleted token stays
deleted however the pods restart. On one already running, create a normal
token and delete `initial`.

Name a Secret wherever the manifests are rendered with no cluster behind them —
`helm template`, Argo CD — since there is nothing to reuse there and every
render would otherwise carry a different token. Setting
`bindizr.api.authentication.initialToken.enabled=false` leaves the first token
to `bindizr token create` in the pod instead.

The Secret is mounted as a file rather than put in the environment, keeping it
out of the pod spec.

Clients that sign RFC 2136 updates — cert-manager's DNS-01 solver, a DHCP
server — need a TSIG key, which the chart does not seed: with the token above,
any workload creates one over the API.

```bash
$ curl -X POST http://bindizr-bindizr-chart-api:8000/tsig-keys \
  -H "Authorization: Bearer $BINDIZR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "update-key", "is_global": true}'
```

The secret comes back once, in that response. A global key updates every zone
without a grant; prefer a scoped key where you can grant — see
[Dynamic Updates](../cli/nsupdate.md).

## Serving the API over TLS

The API is `ClusterIP` and carries bearer tokens, so anything reaching it from
outside the cluster needs TLS. Point the chart at a Secret holding `tls.crt`
and `tls.key` — a cert-manager `Certificate` produces one — and bindizr serves
HTTPS itself:

```bash
$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --reuse-values --set bindizr.api.tls.existingSecret=bindizr-api-tls
```

The readiness probe follows to HTTPS on its own. Leave the value empty when an
Ingress terminates TLS in front instead; the Service stays `ClusterIP` either
way, so bindizr's own port is never reachable from outside.

!!! note "SQLite is not supported by the Helm chart"

    A pod-local SQLite file cannot be shared across replicas or survive
    rescheduling. Use MySQL or PostgreSQL on Kubernetes.

See the [chart documentation](https://github.com/kweonminsung/bindizr/blob/main/charts/README.md)
for all Helm values and examples, including bindizr-ui.
