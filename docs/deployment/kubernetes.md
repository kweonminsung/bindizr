# Kubernetes

The Helm chart installs Bindizr and BIND secondaries. This walkthrough uses
bundled PostgreSQL to create and query a first zone, then covers production
settings.

## What the chart deploys

By default, the chart runs two Bindizr pods and two BIND pods. BIND discovers
zones from Bindizr's catalog and answers client queries. Enabling `postgresql`
or `mysql` adds a single database pod.

## 1. Install

For a first look, let the chart run PostgreSQL:

```bash
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr --create-namespace \
  --set postgresql.enabled=true
```

Resource names are the release name plus the chart name, so with the command
above the Deployment is `bindizr-bindizr-chart` and the Services
`bindizr-bindizr-chart-api` and `bindizr-bindizr-chart-bind9`. Check that
the pods are ready:

```bash
kubectl get pods -n bindizr
```

Example output:

```text
NAME                                      READY   STATUS    RESTARTS   AGE
bindizr-bindizr-chart-6d9c7f8b5-2xk4q     1/1     Running   0          70s
bindizr-bindizr-chart-6d9c7f8b5-p7vzd     1/1     Running   1          70s
bindizr-bindizr-chart-bind9-0             1/1     Running   0          70s
bindizr-bindizr-chart-bind9-1             1/1     Running   0          70s
bindizr-bindizr-chart-postgresql-0        1/1     Running   0          70s
```

If a pod restarts during database initialization, check
[Troubleshooting](../troubleshooting.md#the-daemon).

The CLI has no remote mode; it runs inside the pod through `kubectl exec`.
`bindizr doctor` checks the whole path, from the database to the BIND pods:

```bash
kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- bindizr doctor
```

## 2. Create a zone

The CLI in the pod needs no token. Create a zone and add a record to look up;
zone creation includes an apex `NS` record naming `--mname`:

```bash
kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr record create example.com www --type A --value 192.0.2.1
```

Bindizr notifies the BIND pods after each change. `zone status` shows the
serial each serves and reports `in sync` when it has caught up:

```bash
kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- bindizr zone status example.com
```

## 3. Query it

BIND answers, not Bindizr, so the query goes to the `bind9` Service. The
quickest look is a port-forward. It carries TCP only, so `dig` is told to
use TCP:

```bash
kubectl port-forward -n bindizr svc/bindizr-bindizr-chart-bind9 5353:53
```

In another terminal:

```bash
dig +tcp @127.0.0.1 -p 5353 www.example.com A +short
# Expected answer: 192.0.2.1
```

Real clients need the Service to have an address of its own — see
[Reaching the BIND secondaries](#reaching-the-bind-secondaries).

## 4. The first API token

Authentication is on by default, so the HTTP API answers `401` until a token
exists. The chart seeds none; the first one is created with the CLI in the
pod:

```bash
kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr token create admin --role admin
```

The secret is printed once and cannot be shown again, so a lost token is
replaced rather than recovered. Keep it with your other deployment secrets.
The HTTP API's Service is `ClusterIP`; a port-forward reaches it from outside:

```bash
kubectl port-forward -n bindizr svc/bindizr-bindizr-chart-api 8000:8000
```

In another terminal, set `BINDIZR_TOKEN` to the secret you saved and call the API:

```bash
export BINDIZR_TOKEN='<your-token>'
curl -H "Authorization: Bearer $BINDIZR_TOKEN" http://127.0.0.1:8000/zones
```

Hand out further tokens from this one, each in a role granted only what it
needs — see [Access Control](../cli/access-control.md). Clients that update zones themselves
(cert-manager's DNS-01 solver, a DHCP server) sign with a TSIG key instead,
created over the HTTP API with this token — see
[Dynamic Updates](../cli/nsupdate.md#the-first-key).

## Production: external database

Point the chart at your own MySQL or PostgreSQL through a Secret holding the
connection URL, and leave the bundled database off:

```bash
kubectl create namespace bindizr
kubectl create secret generic bindizr-db-secret -n bindizr \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'

helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

For MySQL, add `--set bindizr.database.type=mysql`.

!!! note "SQLite is not supported by the Helm chart"

    A pod-local SQLite file cannot be shared across replicas or survive
    rescheduling. Use MySQL or PostgreSQL on Kubernetes.

## Reaching the BIND secondaries

Clients query the `bindizr-bindizr-chart-bind9` Service, whose default type is
`LoadBalancer`. Point your name servers' address records at its external IP.
On a cluster without a load balancer provider, use `NodePort` for direct testing:

```bash
helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr --reuse-values \
  --set bind9.service.type=NodePort --set bind9.service.nodePort=30053
dig @<node-ip> -p 30053 www.example.com A +short
```

Public DNS delegation needs TCP and UDP port 53. A NodePort such as 30053
requires a load balancer or port mapping before ordinary resolvers can use it.

The other `bind9.*` values: `bind9.replicas`, `bind9.image` (the ISC image
is amd64-only; the kind example carries an arm64 overlay),
`bind9.persistence` for a volume per pod, and `bind9.service.annotations`
for the load balancer.

## Secondaries outside the chart

Bindizr sends NOTIFY to, and accepts transfers from, the secondaries
registered with it — see [Secondaries](../cli/secondaries.md). They live in
the database, and a starting Bindizr pod registers the BIND pods by their
headless names. A secondary elsewhere, an existing BIND for instance, is
registered the same way through `bindizr.dns.extraSecondaries`, each with a
name and a `host[:port]` address:

```bash
helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr --reuse-values \
  --set 'bindizr.dns.extraSecondaries[0].name=ns2' \
  --set 'bindizr.dns.extraSecondaries[0].address=ns2.example.net:53'
```

A changed value rolls the Bindizr pods, which register the new secondary at
start, so it is notified from the next change on; one removed from the value
stays registered until `bindizr secondary delete` in the pod forgets it. That server has to reach Bindizr's DNS Service in turn, `bindizr-bindizr-chart-dns`,
which the chart keeps `ClusterIP`: expose it yourself and point the
secondary's catalog zone at it.

## Serving the HTTP API over TLS

The HTTP API carries bearer tokens, so anything reaching it from outside the
cluster needs TLS. Point the chart at a Secret holding `tls.crt` and
`tls.key` — a cert-manager `Certificate` produces one — and Bindizr serves
HTTPS itself:

```bash
helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr --reuse-values --set bindizr.api.tls.existingSecret=bindizr-api-tls
```

The readiness probe follows to HTTPS on its own. Leave the value empty when
an Ingress terminates TLS in front instead; with `bindizr.api.service.type`
left at `ClusterIP`, Bindizr's own port is then never reachable from outside.

## Trying it on kind

[examples/kind/](https://github.com/kweonminsung/bindizr/tree/main/examples/kind)
holds a three-node kind cluster and the values that install the chart into
it, with the BIND Service mapped to the host and an optional ExternalDNS
setup; the walkthrough is in
[examples/README.md](https://github.com/kweonminsung/bindizr/blob/main/examples/README.md#kind).

See the [chart documentation](https://github.com/kweonminsung/bindizr/blob/main/charts/README.md)
for all Helm values and examples, including bindizr-ui.
