# bindizr-core

Shared core types and the DNS library for the `bindizr` DNS control plane.

This crate contains the configuration loader, data models, logging, and the Prometheus metrics
registry, plus the DNS library itself: record value types, wire encoding and decoding, DNSSEC
signing, TSIG, and zone-file parsing. It owns the whole `domain` dependency, so no crate above it depends on
`domain` directly.

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-core>
- License: Apache-2.0
