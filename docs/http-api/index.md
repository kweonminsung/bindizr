# HTTP API

Bindizr exposes zones, records, versions, TSIG keys, and tokens over an HTTP
API served on `api.listen_addr:api.listen_port` (`127.0.0.1:3000` by default).

[Open the full API reference :material-open-in-new:](https://kweonminsung.github.io/bindizr/api/){ .md-button .md-button--primary }

The reference is generated from the OpenAPI spec, which is also served directly
at [`openapi.yaml`](../openapi.yaml) if you want to feed it to a client
generator.

## TLS

Requests carry their API token in an `Authorization` header, so the API is
loopback-only out of the box. Anything reachable off the host needs TLS —
point `api.tls_cert_file` and `api.tls_key_file` at a PEM certificate chain
and private key and bindizr serves HTTPS on the same port:

```toml
[api]
listen_addr = "0.0.0.0"
tls_cert_file = "/etc/bindizr/tls/tls.crt"
tls_key_file = "/etc/bindizr/tls/tls.key"
```

Both or neither: half a pair is refused at startup rather than quietly
serving plain HTTP on a port meant to be HTTPS. The files are read once at
startup, so a renewed certificate needs a restart, and `[api]` is fixed while
running — a `config reload` that changes them is refused whole.

A TLS-terminating proxy or Ingress in front is the other way, and the one to
use where certificates are already managed there. Terminating in front leaves
bindizr's own port plain, so keep it on loopback or a private network.

## Listings

Every listing answers the same shape — `items` beside a `pagination` object of
`limit`, `offset`, and `total` — and takes `limit` and `offset` as query
parameters. An omitted `limit` pages at 50; 1000 is the most one call returns.

```bash
$ curl -H "Authorization: Bearer $TOKEN" \
    'http://localhost:3000/tokens?limit=20&offset=40'
```

The CLI reads whole tables instead: it talks to the daemon over its local
socket, which applies no page limit.

`/zones` and `/records` also take `sort` and `order`. The row id follows the
sort column, so paging stays stable even where the column has ties.

`/records?signed=true` pages the zone's derived DNSSEC records after its user
records. They are narrowed by the same name, type, and TTL filters; a `search`
reaches them by name only, since their type is stored as a number and their
rdata as wire bytes, a `priority` filter leaves them out because none carries
one, and a `value` filter is refused rather than answered without them.

## Authentication

Bootstrap the first token with the CLI:

```bash
$ bindizr token create --name admin --global
```

Tokens are scoped by default and act only on the zones they are
[granted](../cli/tokens.md); `--global` covers every zone and the
zone plane.

Then include it in the `Authorization` header:

```bash
$ curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/zones
```

From there a global token manages tokens over HTTP as well — `POST /tokens`
returns the new secret once, `GET /tokens` lists them, `DELETE /tokens/{name}`
revokes one. `GET /tokens/self` describes the token a request carries —
name, scope, expiry, never the secret — and `GET /tokens/self/grants` lists
the grants it holds; both work for scoped tokens too. The CLI stays the
recovery path: if every global token is lost, create a new one on the daemon
host.

Setting `api.require_authentication = false` disables the check entirely — only
sensible when Bindizr is bound to a loopback address or an otherwise trusted
network.

## Unauthenticated endpoints

`GET /health` and `GET /metrics` are always unauthenticated, and neither exposes
zone data. `/health` is part of the OpenAPI spec; `/metrics` is not. See
[Prometheus Metrics](metrics.md).
