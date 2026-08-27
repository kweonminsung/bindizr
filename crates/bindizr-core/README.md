# bindizr-core

Shared core types and the DNS library for the `bindizr` DNS control plane.

This crate contains the configuration loader, data models, and logging support, plus the DNS
library itself: record value types, wire encoding and decoding, DNSSEC signing, TSIG, and
zone-file parsing. It owns the whole `domain` dependency, so no crate above it depends on
`domain` directly.

## Documentation

- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-core>
- License: Apache-2.0
