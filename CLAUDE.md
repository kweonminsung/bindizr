# CLAUDE.md

Guidance for working in this repository.

## Overview

Bindizr is a Rust DNS control plane for BIND9. It manages zones/records via an
HTTP API or CLI, stores them in MySQL / PostgreSQL / SQLite, and propagates
changes to BIND9 secondaries via AXFR/IXFR using DNS Catalog Zones (RFC 9432).
It also serves RFC 2136 dynamic updates (nsupdate).

## Build / Test / Lint

```bash
cargo build -p bindizr                                    # build the binary
cargo build --workspace                                   # build everything
cargo test --workspace --all-features -- --test-threads=1 # full suite (CI cmd)
cargo clippy --workspace                                  # lint
cargo +nightly fmt                                         # format (needs nightly)
```

- Tests **must** run single-threaded (`--test-threads=1`); they share process
  state and will race otherwise.
- `rustfmt.toml` enables unstable features (`imports_granularity`,
  `group_imports`), so formatting requires the **nightly** toolchain. On stable
  `cargo fmt` runs but silently ignores those options.
- `bindizr-e2e` tests drive real DB/BIND9 containers and need Docker; the other
  crates' `--lib` tests run without external services.

## Architecture — workspace crates

- `bindizr-core` — config, logging, DNS value types, DB models.
- `bindizr-db` — repository layer. One impl per backend under
  `repository/{mysql,postgres,sqlite}/`. **The three backends are intentionally
  duplicated** (per-backend SQL + error text); do not try to deduplicate them.
- `bindizr-dns` — XFR server (AXFR/IXFR/catalog/NOTIFY), wire encoding, nsupdate.
- `bindizr-service` — business logic for zones/records (create/update/delete,
  bulk, zone-file import, tokens, serial bumping).
- `bindizr` — the binary: HTTP API (axum), CLI (clap), Unix-socket daemon IPC.
- `bindizr-e2e` — end-to-end API/CLI/DNS tests.

## Conventions

### Comments

Keep comments that explain **why**, document non-obvious behavior/invariants,
protocol/wire-format details, or public-API contracts (`///`). Remove comments
that merely restate the adjacent code. Specifically avoid:

- Trailing scaffolding notes like `id: 0, // Will be set by the database` — the
  placeholder pattern is used throughout and needs no annotation.
- Section labels that echo the code they precede (e.g. `// Table creation
  queries vary by database backend` above the `match self { ... }` that plainly
  does exactly that).

`#[allow(dead_code)]` on repository traits and a few facade methods is
deliberate (trait surface consumed across crates / kept to satisfy lints) —
leave it in place.

### Benchmark results folders

Every benchmark run writes to its own timestamped directory,
**`results_<YYYYmmdd_HHMMSS>/`** (e.g. `results_20260710_233856/`), created in
[`benchmarks/lib/settings.py`](benchmarks/lib/settings.py). This is the single
canonical naming convention — never refer to a bare `results/` directory in
code, docs, or messages. Set `BENCH_RESULTS_DIR` to reuse an existing directory
when re-running a subset of benchmarks (`-b ...`) so the report is rebuilt from
the full raw set.

## Git

- Do **not** add Claude (or any AI assistant) as a `Co-Authored-By` trailer or
  otherwise attribute co-authorship in commit messages. Commits are authored by
  the repository owner only.
- Commit/push only when explicitly asked. Branch off `main` before committing if
  currently on `main`.

## Benchmarks

`benchmarks/` is a self-contained Python + Docker suite (not part of the Cargo
build). `./benchmarks/benchmark.sh` is the entrypoint; benchmark keys are
`b01_crud_tps` … `b09_resource_usage` (query performance is `b08_query_perf`).
Results (`performance.{md,csv,json}` + `graphs/`) and the `results_*/` dirs are
git-ignored.
