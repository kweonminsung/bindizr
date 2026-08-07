# ExternalDNS

Bindizr can act as an [ExternalDNS](https://github.com/kubernetes-sigs/external-dns)
provider: hostnames on Kubernetes Ingresses and Services become records in
zones bindizr manages.

Because the external-dns webhook client cannot send an `Authorization`
header, bindizr ships a small adapter binary (`bindizr-external-dns`, in the
same image) that runs as a sidecar in the external-dns pod and calls the
bindizr API with a token:

```text
external-dns ──127.0.0.1:8888──▶ bindizr-external-dns ──Bearer token──▶ bindizr
```

Validated against external-dns **v0.21.0**.

## Setup

**1. Enable the provider API** on the bindizr server:

```toml
[api]
external_dns_enabled = true
```

**2. Create a token and grant it the zones** external-dns should manage. The
zones must already exist — ExternalDNS never creates or deletes zones:

```bash
$ bindizr token create --name external-dns
$ bindizr zone token-policy add example.com --token external-dns
$ kubectl -n external-dns create secret generic bindizr-external-dns \
    --from-literal=api-token=<token>
```

The token's grants become the ExternalDNS domain filter automatically; a
global token covers every zone. See [API Tokens](cli/tokens.md).

**3. Add the adapter** as a second container in the external-dns Deployment.
The default webhook URL (`http://localhost:8888`) already points at it:

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
```

**4. Annotate a resource** and the record appears in bindizr:

```yaml
metadata:
  annotations:
    external-dns.alpha.kubernetes.io/hostname: app.example.com
```

## What to expect

- **Record types**: A, AAAA, CNAME, and TXT; anything else is rejected with a
  clear error, never silently dropped. Ownership TXT records
  (`--registry=txt`) are stored and returned verbatim.
- **Atomic and idempotent**: one ExternalDNS sync is one bindizr transaction —
  all zones apply together or not at all, and retried requests are no-ops.
- **SOA serials**: only zones with an actual change advance their serial, once
  per sync, with IXFR history for secondaries.
- **TTL**: endpoints without a TTL use the zone's default TTL.
- **Zone matching**: the most-specific existing zone wins
  (`api.internal.example.com` → `internal.example.com`, never the parent).

## Adapter reference

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--bindizr-url` | `BINDIZR_URL` | required |
| `--token` | `BINDIZR_API_TOKEN` | none |
| `--token-file` | `BINDIZR_API_TOKEN_FILE` | none (takes precedence over `--token`) |
| `--listen-addr` | `BINDIZR_EXTERNAL_DNS_LISTEN_ADDR` | `127.0.0.1:8888` |
| `--health-listen-addr` | `BINDIZR_EXTERNAL_DNS_HEALTH_ADDR` | `0.0.0.0:8080` |
| `--timeout-secs` | `BINDIZR_EXTERNAL_DNS_TIMEOUT_SECS` | `10` |
| `--log-level` | `BINDIZR_EXTERNAL_DNS_LOG_LEVEL` | `info` |

The health listener serves `GET /healthz` (also checks bindizr reachability)
and `GET /metrics` (`bindizr_external_dns_requests_total`,
`bindizr_external_dns_request_duration_seconds`).

### Running standalone

If the adapter cannot live in the external-dns pod, run it as its own
Deployment with `--listen-addr 0.0.0.0:8888` and point
`--webhook-provider-url` at its Service. The adapter→bindizr hop stays
authenticated, but external-dns→adapter is then plain HTTP: keep the Service
`ClusterIP`, never expose it through an Ingress, and restrict access to the
external-dns pods with a NetworkPolicy (which limits reachability but does
not authenticate the caller). The sidecar layout is the recommended default.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `401` in the adapter log | Token missing, expired, or wrong |
| `403 API token is not allowed to manage ...` | Grant the zone: `bindizr zone token-policy add <zone> --token <NAME>` |
| `404 No zone is authoritative for '<name>'` | Create the zone first; ExternalDNS never creates zones |
| `502` from the adapter | Bindizr unreachable or 5xx; external-dns retries automatically |
| external-dns exits over a content-type error | The webhook URL does not point at the adapter |
