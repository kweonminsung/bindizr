# bindizr-service

Application service layer for the `bindizr` DNS control plane.

This crate implements the zone, record, serial, API token and TSIG key (with their zone
grants), DNSSEC policy and signing, notification, catalog zone, zone-file import and transfer
from another server, version diff and rollback, RFC 2136 apply, and ExternalDNS apply workflows
used by the Bindizr CLI, HTTP API, and DNS server. It owns authorization and transactions: every
operation a front end can reach takes a caller and gates itself.

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-service>
- License: Apache-2.0
