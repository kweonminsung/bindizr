# HTTP API

Manage zones, records, secondaries, access control, and DNSSEC over HTTP.
The packaged configuration listens on `127.0.0.1:3000`; the Compose and Helm
examples use port `8000`.

[Open the full API reference :material-open-in-new:](https://kweonminsung.github.io/bindizr/api/){ .md-button .md-button--primary }

Download the [OpenAPI specification](../openapi.yaml) for client generation.

## Authentication

Create the first token with the CLI on the daemon host. For a package install:

```bash
sudo bindizr token create admin --role admin
```

In Docker or Kubernetes, run the same command inside the container or pod.
Save the secret when it is printed; it cannot be retrieved later. Use it in
an `Authorization` header:

```bash
export BINDIZR_TOKEN='<your-token>'
curl -H "Authorization: Bearer $BINDIZR_TOKEN" http://127.0.0.1:3000/zones
```

Each token belongs to a [role](../cli/access-control.md). The built-in `admin`
role has full access; create narrower roles for applications. A token with
`access:manage` can create roles and further tokens through the API.
`GET /tokens/self` shows the caller's token metadata, and
`GET /tokens/self/grants` shows its grants.

If all administrator tokens are lost, create a replacement through the CLI.
`api.authentication_required = false` allows full access without a token;
use it only on a trusted network.

## TLS

For access off-host, configure HTTPS or use a TLS-terminating proxy. To serve
HTTPS directly, set both PEM file paths:

```toml
[api]
listen_addr = "0.0.0.0"

[api.tls]
cert_file = "/etc/bindizr/tls/tls.crt"
key_file = "/etc/bindizr/tls/tls.key"
```

Supplying only one file is rejected at startup. Certificates are read at
startup, so restart Bindizr after renewal. All `[api]` settings require a
restart. With a proxy or Ingress terminating TLS, keep Bindizr's HTTP listener
on loopback or a private network.

## Listings

Paginated listings return `items` and a `pagination` object containing
`limit`, `offset`, and `total`. The API defaults to 50 items per page and
accepts at most 1000:

```bash
curl -H "Authorization: Bearer $BINDIZR_TOKEN" \
  'http://127.0.0.1:3000/zones?limit=20&offset=40'
```

`/zones` and `/records` also accept `sort` and `order`; tied values are ordered
by ID. The CLI uses `--limit` and `--offset`, with a default page size of 1000.

To include generated DNSSEC records, use
`GET /records?zone_name=example.com&signed=true`. They follow user records in
the same pagination. Name, type, and TTL filters apply to both; `search`
matches generated records by name only, `priority` excludes them, and
`value` cannot be combined with `signed=true`.

## Rejected requests

Unknown query parameters and body fields return `400`. For example, record
deletion uses `type`; `DELETE /records?...&record_type=A` is rejected.

Errors normally return an object with `error` and `code`. Zone-import
validation errors return `422` with the import report, including per-record
errors; no changes are applied.

## Unauthenticated endpoints

- `GET /health` checks database availability.
- `GET /metrics` serves [Prometheus metrics](metrics.md) when
  `api.metrics_enabled` is on (the default).
- `GET /openapi.json` and `GET /openapi.yaml` serve the API specification when
  `api.openapi_enabled` is on (off by default).

These endpoints do not require an API token. The OpenAPI endpoints describe
the complete API surface; health and metrics expose no zone records.
