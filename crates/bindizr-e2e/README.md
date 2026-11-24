# bindizr-e2e

`tests/e2e.rs` is the single harness binary. It declares four groups: API scenarios under
`tests/api`, CLI scenarios under `tests/cli`, RFC 2136 update scenarios under `tests/nsupdate`, and
zone-transfer scenarios, XoT included, under `tests/xfr`. Shared process/database initialization and
cross-cutting checks live under `tests/common`.

The integration tests use a temporary SQLite database by default and do not require Docker:

```sh
cargo test -p bindizr-e2e
```

Set `BINDIZR_E2E_VERIFY_DNS=true` to run the tests that start through `TestApp::start()` against
the Docker Compose stack instead: Bindizr on PostgreSQL plus two BIND 9 secondaries. Tests that need
a non-default configuration or the host filesystem (`start_with_options` / `start_local`, among
them the whole `nsupdate` group and the TLS and config-reload tests) still spawn a local Bindizr
with a temporary SQLite database. After a successful write through the shared API helper or a
covered CLI command, the harness waits for both BIND secondaries to serve the API's records for
enabled zones with an apex NS. Covered CLI commands include `zone`/`record` create, bulk-create,
update, delete, import, notify, and zone version rollback. For record updates and deletions by ID,
the harness also checks that a name and type removed from a served zone no longer answers. The
delete-by-name test checks removal of the selected type explicitly. The DNSSEC propagation,
`doctor`, `daemon`, and zone-status tests run their secondary checks only here.
`bind9-1` pulls over TLS (XoT) under a TSIG key, and `bind9-2` pulls over plain TCP by address:

```sh
BINDIZR_E2E_VERIFY_DNS=true cargo test -p bindizr-e2e
```

On ARM hosts (e.g. Apple Silicon), additionally set `BINDIZR_E2E_ARM=true` to layer
`docker-compose.arm.yml` on top of the stack. It swaps the amd64-only ISC BIND image for the
multi-arch `ubuntu/bind9` image so the secondaries run natively instead of under emulation:

```sh
BINDIZR_E2E_VERIFY_DNS=true BINDIZR_E2E_ARM=true cargo test -p bindizr-e2e
```

The harness leaves the stack running and reuses it on later runs without rebuilding, so run
`docker compose -p bindizr-e2e-dns down -v` after changing Bindizr code and when switching between
the ARM and default stacks.
