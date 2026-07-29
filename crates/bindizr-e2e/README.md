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

On ARM hosts (e.g. Apple Silicon), additionally set `BINDIZR_E2E_ARM=true` to layer
`docker-compose.arm.yml` on top of the stack. It swaps the amd64-only ISC BIND9 image for the
multi-arch `ubuntu/bind9` image so the secondaries run natively instead of under emulation:

```sh
BINDIZR_E2E_VERIFY_DNS=true BINDIZR_E2E_ARM=true cargo test -p bindizr-e2e
```

When switching between the ARM and default stacks, remove the old containers and volumes first:
`docker compose -p bindizr-e2e-dns down -v`.
