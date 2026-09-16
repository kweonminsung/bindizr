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

Authentication is on by default, so the API answers `401` until a token
exists. Rather than `kubectl exec` into the pod, hand the chart a secret and
bindizr creates a global token with it on the first start that finds none:

```bash
$ kubectl create secret generic bindizr-initial-token --from-literal=api-token="$(openssl rand -hex 24)"

$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --reuse-values \
  --set bindizr.api.authentication.initialToken.existingSecret=bindizr-initial-token
```

It seeds rather than resets: once any token exists, later starts ignore it.
Rotate by creating a normal token and deleting `initial`.

nsupdate takes the same shape. A cluster whose clients sign RFC 2136 updates —
cert-manager's DNS-01 solver, a DHCP server — needs a TSIG key before any of
them can write, and `bindizr.dns.nsupdate.initialKey` seeds one:

```bash
$ kubectl create secret generic bindizr-initial-key \
  --from-literal=secret="$(openssl rand -base64 32)"

$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --reuse-values \
  --set bindizr.dns.nsupdate.initialKey.name=update-key \
  --set bindizr.dns.nsupdate.initialKey.existingSecret=bindizr-initial-key
```

That key is global: it may update every zone without a grant, which is the
only useful shape for a key created before any grant exists. Where the API is
reachable, create a scoped key and grant it instead — see
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
