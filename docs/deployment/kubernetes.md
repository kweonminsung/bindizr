# Kubernetes

Bindizr runs on Kubernetes through its Helm chart, which installs it together
with the BIND servers that answer for it and can bring a PostgreSQL or MySQL
of its own for a first look. This page walks from `helm install` to a zone
that answers a query, then covers the settings a real cluster needs.

## What the chart deploys

Bindizr never answers a client's DNS query itself. It keeps the zones in a
database and hands them to BIND over zone transfer; BIND answers the
queries. The chart runs both, two pods each, and BIND learns which zones
exist from Bindizr's catalog zone, so nothing is configured on it by hand.
Enable `postgresql` or `mysql` and a single-replica database joins them.
[Deployment Options](index.md) explains how the two halves talk.

## 1. Install

For a first look, let the chart run PostgreSQL:

```bash
$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr --create-namespace \
  --set postgresql.enabled=true
```

Resource names are the release name plus the chart name, so with the command
above the Deployment is `bindizr-bindizr-chart` and the Services
`bindizr-bindizr-chart-api` and `bindizr-bindizr-chart-bind9`. After a
minute every pod is `Running`:

```bash
$ kubectl get pods -n bindizr
NAME                                      READY   STATUS    RESTARTS   AGE
bindizr-bindizr-chart-6d9c7f8b5-2xk4q     1/1     Running   0          70s
bindizr-bindizr-chart-6d9c7f8b5-p7vzd     1/1     Running   1          70s
bindizr-bindizr-chart-bind9-0             1/1     Running   0          70s
bindizr-bindizr-chart-bind9-1             1/1     Running   0          70s
bindizr-bindizr-chart-postgresql-0        1/1     Running   0          70s
```

One `bindizr` pod may show a single restart on a first install: both
replicas create the database tables at once and PostgreSQL lets only one
win. It does not recur — see [Troubleshooting](../troubleshooting.md#the-daemon).

The CLI has no remote mode; it runs inside the pod through `kubectl exec`.
`bindizr doctor` checks the whole path, from the database to the BIND pods:

```bash
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- bindizr doctor
```

## 2. Create a zone

The CLI in the pod needs no token. Create a zone, give it its `NS` record
(BIND will not load a zone without one), and add a record to look up:

```bash
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr record create example.com @ --type NS --value ns1.example.com
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr record create example.com www --type A --value 192.0.2.1
```

Bindizr notifies the BIND pods after each change and they pull the zone
within a second. `zone status` lists each pod with the serial it serves,
`in_sync` once it has caught up:

```bash
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- bindizr zone status example.com
```

## 3. Query it

BIND answers, not Bindizr, so the query goes to the `bind9` Service. The
quickest look is a port-forward. It carries TCP only, so `dig` is told to
use TCP:

```bash
$ kubectl port-forward -n bindizr svc/bindizr-bindizr-chart-bind9 5353:53
```

In another terminal:

```bash
$ dig +tcp @127.0.0.1 -p 5353 www.example.com A +short
192.0.2.1
```

Real clients need the Service to have an address of its own — see
[Reaching the BIND secondaries](#reaching-the-bind9-secondaries).

## 4. The first API token

Authentication is on by default, so the HTTP API answers `401` until a token
exists. The chart seeds none; the first one is created with the CLI in the
pod:

```bash
$ kubectl exec -n bindizr deploy/bindizr-bindizr-chart -- \
  bindizr token create admin --global
```

The secret is printed once and cannot be shown again, so a lost token is
replaced rather than recovered. Keep it with your other deployment secrets.
The HTTP API's Service is `ClusterIP`; a port-forward reaches it from outside:

```bash
$ kubectl port-forward -n bindizr svc/bindizr-bindizr-chart-api 8000:8000
$ curl -H "Authorization: Bearer $BINDIZR_TOKEN" http://127.0.0.1:8000/zones
```

Hand out further tokens from this one, each scoped to the zones it needs —
see [API Tokens](../cli/tokens.md). Clients that update zones themselves
(cert-manager's DNS-01 solver, a DHCP server) sign with a TSIG key instead,
created over the HTTP API with this token — see
[Dynamic Updates](../cli/nsupdate.md#the-first-key).

## Production: external database

Point the chart at your own MySQL or PostgreSQL through a Secret holding the
connection URL, and leave the bundled database off:

```bash
$ kubectl create namespace bindizr
$ kubectl create secret generic bindizr-db-secret -n bindizr \
  --from-literal=database-url='postgresql://user:password@postgresql:5432/bindizr'

$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 -n bindizr \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

For MySQL, add `--set bindizr.database.type=mysql`.

!!! note "SQLite is not supported by the Helm chart"

    A pod-local SQLite file cannot be shared across replicas or survive
    rescheduling. Use MySQL or PostgreSQL on Kubernetes.

## Reaching the BIND secondaries

Clients query the `<release>-bind9` Service; its address is what the zones'
`NS` records point at. Its type, `bind9.service.type`, is `LoadBalancer`.
Where nothing provisions one — kind, bare metal without MetalLB — the
external IP stays `<pending>` forever. Use `NodePort` there, and pin the
port with `bind9.service.nodePort` so it does not change between installs:

```bash
$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  -n bindizr --reuse-values \
  --set bind9.service.type=NodePort --set bind9.service.nodePort=30053
$ dig @<node-ip> -p 30053 www.example.com A +short
```

The other `bind9.*` values: `bind9.replicas`, `bind9.image` (the ISC image
is amd64-only; the kind example carries an arm64 overlay),
`bind9.persistence` for a volume per pod, and `bind9.service.annotations`
for the load balancer.

## Secondaries outside the chart

Bindizr sends NOTIFY to, and accepts transfers from, the servers listed in
`dns.secondary_addrs` — see [Configuration](../configuration.md#secondaries).
The chart fills the list with the BIND pods. A secondary elsewhere, an
existing BIND for instance, is appended with `bindizr.dns.extraSecondaryAddrs`:

```bash
$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  -n bindizr --reuse-values \
  --set 'bindizr.dns.extraSecondaryAddrs={ns2.example.net:53,192.0.2.7}'
```

That server has to reach Bindizr's DNS Service in turn, `<release>-dns`,
which the chart keeps `ClusterIP`: expose it yourself and point the
secondary's catalog zone at it.

## Serving the HTTP API over TLS

The HTTP API carries bearer tokens, so anything reaching it from outside the
cluster needs TLS. Point the chart at a Secret holding `tls.crt` and
`tls.key` — a cert-manager `Certificate` produces one — and Bindizr serves
HTTPS itself:

```bash
$ helm upgrade bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  -n bindizr --reuse-values --set bindizr.api.tls.existingSecret=bindizr-api-tls
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
