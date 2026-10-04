# bindizr-external-dns

ExternalDNS webhook provider adapter for the `bindizr` DNS control plane.

This crate serves the ExternalDNS webhook protocol on a localhost listener and forwards every
operation to Bindizr's HTTP API with a Bearer token. It holds no DNS logic and no state of its
own; Bindizr's `/external-dns` endpoints do the work (enable them with
`api.external_dns_enabled`).

The API token's role is the domain filter: ExternalDNS may only touch the zones and subtrees where
the role's grants (`bindizr role grant`) hold all of `record:read`, `record:create`, and
`record:delete`.

```bash
bindizr-external-dns --bindizr-url http://bindizr:8000 --token-file /run/secrets/bindizr-token
```

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-external-dns>
- License: Apache-2.0
