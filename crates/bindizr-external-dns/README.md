# bindizr-external-dns

ExternalDNS webhook provider adapter for the `bindizr` DNS control plane.

This crate serves the ExternalDNS webhook protocol on a localhost listener and forwards every
operation to bindizr's HTTP API with a Bearer token. It holds no DNS logic and no state of its
own; bindizr's `/external-dns` endpoints do the work (enable them with
`api.external_dns_enabled`).

The API token's zone grants are the domain filter: ExternalDNS may only touch zones the token has
been granted with `bindizr token grant`.

```bash
bindizr-external-dns --bindizr-url http://bindizr:8000 --token-file /run/secrets/bindizr-token
```

## Documentation

- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-external-dns>
- License: Apache-2.0
