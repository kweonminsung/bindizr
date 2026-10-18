# bindizr-db

Database access for the `bindizr` DNS control plane.

This crate owns Bindizr's database pool setup, schema initialization, and the `Db` and
`Transaction` enums whose entity modules run the queries for zones, records, roles with their
grants, API tokens and TSIG keys, secondaries and the transfers served to them, the audit log,
zone versions, the IXFR journal, DNSSEC policies, keys, records, and DS withdrawals, and catalog
zone state. MySQL, PostgreSQL, and SQLite each get their own implementation.

## Documentation

- Documentation site: <https://kweonminsung.github.io/bindizr/>
- Repository: <https://github.com/kweonminsung/bindizr>
- API documentation: <https://docs.rs/bindizr-db>
- License: Apache-2.0
