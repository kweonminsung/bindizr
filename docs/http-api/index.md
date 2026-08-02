# HTTP API

Bindizr exposes zones, records, snapshots, TSIG keys, and tokens over an HTTP
API served on `api.listen_addr:api.listen_port` (`127.0.0.1:3000` by default).

[Open the full API reference :material-open-in-new:](https://kweonminsung.github.io/bindizr/api/){ .md-button .md-button--primary }

The reference is generated from the OpenAPI spec, which is also served directly
at [`openapi.yaml`](../openapi.yaml) if you want to feed it to a client
generator.

## Authentication

Create a token with the CLI:

```bash
$ bindizr token create --description "API access for monitoring"
```

Then include it in the `Authorization` header:

```bash
$ curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:3000/zones
```

Setting `api.require_authentication = false` disables the check entirely — only
sensible when Bindizr is bound to a loopback address or an otherwise trusted
network.

## Unauthenticated endpoints

`GET /health` and `GET /metrics` are always unauthenticated and are not part of
the OpenAPI spec. Neither exposes zone data. See
[Prometheus Metrics](metrics.md).
