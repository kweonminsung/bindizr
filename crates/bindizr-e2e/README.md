# bindizr-e2e

API scenarios live under `tests/api`, CLI scenarios under `tests/cli`, and shared process/database
initialization and cross-cutting checks live under `tests/common`.

The integration tests use a temporary SQLite database by default and do not require Docker:

```sh
cargo test -p bindizr-e2e
```

Set `BINDIZR_E2E_VERIFY_DNS=true` to select the Docker Compose environment instead. In this mode
the host SQLite database and local bindizr process are not initialized. The record CRUD scenario
also verifies that create, update, and delete results reach both BIND9 secondaries:

```sh
BINDIZR_E2E_VERIFY_DNS=true cargo test -p bindizr-e2e
```
