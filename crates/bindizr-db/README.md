# bindizr-db

Database repository implementations for the `bindizr` DNS control plane.

This crate owns bindizr's database pool setup, schema initialization, and repository traits for
zones, records, API tokens and TSIG keys with their zone grants, zone versions, the IXFR
journal, DNSSEC policies, keys, records, and DS withdrawals, and catalog zone state. MySQL, PostgreSQL, and SQLite
each get their own implementation.

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-db>
- License: Apache-2.0
