# bindizr-service

Application service layer for the `bindizr` DNS control plane.

This crate implements the zone, record, token, serial, authentication, notification, catalog
zone, DNSSEC signing, zone-file import, version rollback, and RFC 2136 apply workflows used by
the bindizr CLI, HTTP API, and DNS server. It owns authorization and transactions: every
operation a front end can reach takes a caller and gates itself.

## Documentation

- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-service>
- License: Apache-2.0
