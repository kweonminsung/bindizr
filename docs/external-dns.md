# ExternalDNS

Bindizr can act as an [ExternalDNS](https://github.com/kubernetes-sigs/external-dns)
provider: hostnames on Kubernetes Ingresses and Services become records in
zones Bindizr manages.

Because the external-dns webhook client cannot send an `Authorization`
header, Bindizr ships a small adapter binary (`bindizr-external-dns`, in the
same image) that runs as a sidecar in the external-dns pod and calls the
HTTP API with a token:

```text
external-dns ──127.0.0.1:8888──▶ bindizr-external-dns ──Bearer token──▶ bindizr
```

Validated against external-dns **v0.21.0**.

## 1. Enable the provider API

On the Bindizr server:

```toml
[api]
external_dns_enabled = true
```

## 2. Create a role and a token

Give a role the record rights ExternalDNS needs in the zones it should manage:
all three of `record:read`, `record:create`, and `record:delete`. One sync
reads ownership records, adds, and deletes as one transaction, so a grant
missing any of them is left out of the domain filter entirely; ExternalDNS
never uses `record:update`. The zones must already exist — ExternalDNS never
creates or deletes zones. Then create the adapter's token in that role:

```bash
$ bindizr role create external-dns-prod
$ bindizr role grant external-dns-prod --zone example.com \
    --actions record:read,record:create,record:delete
$ bindizr token create cluster-a --role external-dns-prod
$ kubectl -n external-dns create secret generic bindizr-external-dns \
    --from-literal=api-token=<token>
```

The role's qualifying grants become the ExternalDNS domain filter
automatically; a grant without `--zone` covers every zone. One role can serve
several clusters, each with a token of its own. See
[Access Control](cli/access-control.md#externaldns).

A grant narrowed by `--pattern` or `--types` works, with limits the domain
filter imposes — see
[How grants become the domain filter](external-dns/advanced.md#how-grants-become-the-domain-filter).

## 3. Add the adapter

It runs as a second container in the external-dns Deployment; the default
webhook URL (`http://localhost:8888`) already points at it:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  template:
    spec:
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.21.0
          args:
            - --source=ingress
            - --provider=webhook
            - --registry=txt
            - --txt-owner-id=my-cluster
        - name: bindizr-external-dns
          image: kweonminsung/bindizr:latest
          command: ["bindizr-external-dns"]
          args:
            - --bindizr-url=http://bindizr.bindizr.svc:8000
          env:
            - name: BINDIZR_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: bindizr-external-dns
                  key: api-token
          ports:
            - containerPort: 8080 # /healthz and /metrics; 8888 stays pod-local
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
```

`/healthz` asks Bindizr with the adapter's own token, so a token that was
rotated away, or whose role reaches no zone, turns the sidecar unready instead of
leaving it green while every sync fails. Every adapter flag, and running it
outside the external-dns pod, is in the
[Adapter reference](external-dns/advanced.md#adapter-reference).

## 4. Annotate a resource

The record appears in Bindizr:

```yaml
metadata:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: app.example.com
```

Which record types are accepted, how a sync applies, and how zones are matched
is in [What to expect](external-dns/advanced.md#what-to-expect).

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `401` in the adapter log | Token missing, expired, or wrong |
| `403` every sync; allowed changes never apply | The grant is restricted by record type, to the apex, or to one exact name — narrowings the domain filter cannot express — and a sync is all-or-nothing. Widen the grant, or narrow external-dns's own `--domain-filter` to what it covers |
| `404 No zone is authoritative for '<name>'` | Either no zone covers the name, or the token's role has no grant reaching the zone that does; the two read alike so a token cannot probe for zones. Create the zone if it is missing (ExternalDNS never creates zones), otherwise grant it: `bindizr role grant <ROLE_NAME> --zone <zone> --actions record:read,record:create,record:delete` |
| `502` from the adapter | Bindizr unreachable or 5xx; external-dns retries automatically |
| `503 no manageable names` at startup | The token's role has no grant holding all of `record:read`, `record:create`, and `record:delete` in an existing zone (or no zones exist yet). Grant one: `bindizr role grant <ROLE_NAME> --zone <zone> --actions record:read,record:create,record:delete`; negotiation recovers on its own |
| `502` although the records were applied | With `dns.notify.batch_ms = 0`, NOTIFY retries to an unreachable secondary can outlast the adapter's timeout after the change already committed. Set a `dns.notify.batch_ms` window so the write is answered at commit, or raise `--timeout-secs`; the retried sync is a no-op |
| external-dns exits over a content-type error | The webhook URL does not point at the adapter |
