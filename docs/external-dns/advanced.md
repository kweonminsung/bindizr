# Advanced ExternalDNS

How the [ExternalDNS](../external-dns.md) provider decides what ExternalDNS may
manage, how a sync is applied, and the adapter's full reference.

## How grants become the domain filter

`GET /external-dns/domains` builds the domain filter ExternalDNS negotiates at
startup from the token role's grants. A grant's name enters it only when the
role holds all three of `record:read`, `record:create`, and `record:delete`
there for a record type in common that ExternalDNS writes (A, AAAA, CNAME, or
TXT), in grants whose patterns cover that name: one sync reads ownership records, adds, and deletes as one
transaction, so a name missing any of them would only fail every sync it
reaches. `record:update` is never used. A grant without `--zone` contributes
every existing zone.

A grant narrowed to a subtree (`--pattern '*.k8s'`) filters to that subtree
rather than its zone, so ExternalDNS plans inside it. A filter entry always
covers the name and everything under it, which is all ExternalDNS can express:
a grant narrowed by record type, to the apex, or to one exact name reads wider
there than it is, and ExternalDNS will plan changes Bindizr rejects. Keep the
type list covering what your sources produce, TXT included, or ownership
records (`--registry=txt`) fail.

## What to expect

- **Record types**: A, AAAA, CNAME, and TXT; anything else is rejected with a
  clear error, never silently dropped. Ownership TXT records
  (`--registry=txt`) are stored and returned verbatim.
- **Atomic and idempotent**: one ExternalDNS sync applies as a whole — every
  zone in it or none — and retried requests are no-ops.
- **SOA serials**: only zones with an actual change advance their serial, once
  per sync, with IXFR history for secondaries.
- **TTL**: records without a TTL use the zone's default TTL.
- **Zone matching**: the most-specific existing zone wins
  (`api.internal.example.com` → `internal.example.com`, never the parent).

## Adapter reference

| Flag | Environment variable | Default |
| --- | --- | --- |
| `--bindizr-url` | `BINDIZR_URL` | required |
| `--token` | `BINDIZR_API_TOKEN` | none |
| `--token-file` | `BINDIZR_API_TOKEN_FILE` | none (takes precedence over `--token`) |
| `--ca-file` | `BINDIZR_CA_FILE` | none (added to the system roots; needed for a private or self-signed Bindizr certificate) |
| `--listen-addr` | `BINDIZR_EXTERNAL_DNS_LISTEN_ADDR` | `127.0.0.1:8888` |
| `--health-listen-addr` | `BINDIZR_EXTERNAL_DNS_HEALTH_ADDR` | `0.0.0.0:8080` |
| `--timeout-secs` | `BINDIZR_EXTERNAL_DNS_TIMEOUT_SECS` | `8` (keep under external-dns's 10s webhook write timeout) |
| `--log-level` | `BINDIZR_EXTERNAL_DNS_LOG_LEVEL` | `info` |

The health listener serves `GET /healthz` (Bindizr answers and accepts this
token) and `GET /metrics` (`bindizr_external_dns_requests_total`,
`bindizr_external_dns_request_duration_seconds`).

### Running standalone

If the adapter cannot live in the external-dns pod, run it as its own
Deployment with `--listen-addr 0.0.0.0:8888` and point
`--webhook-provider-url` at its Service. The adapter→Bindizr hop stays
authenticated, but external-dns→adapter is then plain HTTP: keep the Service
`ClusterIP`, never expose it through an Ingress, and restrict access to the
external-dns pods with a NetworkPolicy. The sidecar layout is the
recommended default.
