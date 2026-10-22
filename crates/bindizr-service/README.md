# bindizr-service

Application service layer for the `bindizr` DNS control plane.

This crate implements the zone, record, serial, role, API token and TSIG key, secondary, audit
log, DNSSEC policy and signing, notification, catalog zone, zone-file import and transfer from
another server, version diff and rollback, RFC 2136 apply, and ExternalDNS apply workflows used
by the Bindizr CLI, HTTP API, and DNS server. It holds the shared `Context`, makes the outbound
DNS calls (NOTIFY, SOA and parent-DS probes, inbound AXFR), and records what the DNS server served
each client. It owns authorization and transactions: every management operation a front end can
reach takes a caller and gates itself; a token's reads of itself take the authenticated token.

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-service>
- License: Apache-2.0
