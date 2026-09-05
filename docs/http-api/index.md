# HTTP API

Bindizr exposes zones, records, versions, TSIG keys, and tokens over an HTTP
API served on `api.listen_addr:api.listen_port` (`127.0.0.1:3000` by default).

[Open the full API reference :material-open-in-new:](https://kweonminsung.github.io/bindizr/api/){ .md-button .md-button--primary }

The reference is generated from the OpenAPI spec, which is also served directly
at [`openapi.yaml`](../openapi.yaml) if you want to feed it to a client
generator.

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
name, scope, expiry, never the secret — and works for scoped tokens too. The
CLI stays the recovery path: if every global token is lost, create a new one
on the daemon host.

Setting `api.require_authentication = false` disables the check entirely — only
sensible when Bindizr is bound to a loopback address or an otherwise trusted
network.

## Unauthenticated endpoints

`GET /health` and `GET /metrics` are always unauthenticated, and neither exposes
zone data. `/health` is part of the OpenAPI spec; `/metrics` is not. See
[Prometheus Metrics](metrics.md).
