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

On the Bindizr server, enable the provider API and restart the daemon:

```toml
[api]
external_dns_enabled = true
```

## 2. Create a role and a token

Create the target zones first. Grant the adapter's role the three actions
ExternalDNS needs, `record:read`, `record:create`, and `record:delete`, in one
grant or several.
ExternalDNS manages records in existing zones; it does not create zones.

```bash
bindizr role create external-dns-prod
bindizr role grant external-dns-prod --zone example.com \
    --actions record:read,record:create,record:delete
bindizr token create cluster-a --role external-dns-prod
export BINDIZR_TOKEN='paste-the-secret-printed-above'
kubectl create namespace external-dns
kubectl -n external-dns create secret generic bindizr-external-dns \
    --from-literal=api-token="$BINDIZR_TOKEN"
```

The role's qualifying grants become the ExternalDNS domain filter
automatically; a grant without `--zone` covers all zones. One role can serve
several clusters, each with a token of its own. See
[Access Control](cli/access-control.md#externaldns).

A grant narrowed by `--pattern` or `--types` works, with limits the domain
filter imposes — see
[How grants become the domain filter](external-dns/advanced.md#how-grants-become-the-domain-filter).

## 3. Add the adapter

Add the following containers to an existing ExternalDNS Deployment in the
`external-dns` namespace. This is a pod-template excerpt; retain the
Deployment's labels, selector, service account, and Kubernetes RBAC.
Replace `--bindizr-url` with your Bindizr API Service URL (for the Helm
quickstart, `http://bindizr-bindizr-chart-api.bindizr.svc:8000`).

The default webhook URL, `http://localhost:8888`, points at the adapter:

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
          image: kweonminsung/bindizr:0.1.0-rc.2
          command: ["bindizr-external-dns"]
          args:
            - --bindizr-url=http://bindizr-bindizr-chart-api.bindizr.svc:8000
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

`/healthz` checks that Bindizr accepts the token and exposes manageable names.
It reports the sidecar unready if either check fails. All flags and standalone
deployment options are in the
[Adapter reference](external-dns/advanced.md#adapter-reference).

## 4. Annotate a resource

Add a hostname annotation to an Ingress, matching `--source=ingress` above:

```yaml
metadata:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: app.example.com
```

For Service annotations, also enable `--source=service`. After a sync, inspect
the result with `bindizr record list example.com` and query your secondary.

Which record types are accepted, how a sync applies, and how zones are matched
is in [What to expect](external-dns/advanced.md#what-to-expect).

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `401` in the adapter log | Token missing, expired, or wrong |
| `403` every sync; allowed changes never apply | The grant is restricted by record type, to the apex, or to one exact name — narrowings the domain filter cannot express — and a sync is all-or-nothing. Widen the grant, or narrow external-dns's own `--domain-filter` to what it covers |
| `404 No zone is authoritative for '<name>'` | Either no zone covers the name, or the token's role has no grant reaching the zone that does; the two read alike so a token cannot probe for zones. Create the zone if it is missing (ExternalDNS never creates zones), otherwise grant it: `bindizr role grant <ROLE_NAME> --zone <zone> --actions record:read,record:create,record:delete` |
| `502` from the adapter | Bindizr unreachable or 5xx; external-dns retries automatically |
| `503 no manageable names` at startup | The token's role has no grant holding all of `record:read`, `record:create`, and `record:delete` for a type ExternalDNS writes (A, AAAA, CNAME, TXT) in an existing zone (or no zones exist yet). Grant one: `bindizr role grant <ROLE_NAME> --zone <zone> --actions record:read,record:create,record:delete`; negotiation recovers on its own |
| `502` although the records were applied | With `dns.notify.batch_ms = 0`, NOTIFY retries to an unreachable secondary can outlast the adapter's timeout after the change already committed. Set a `dns.notify.batch_ms` window so the write is answered at commit, or raise `--timeout-secs`; the retried sync is a no-op |
| external-dns exits over a content-type error | The webhook URL does not point at the adapter |
