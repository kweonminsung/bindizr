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
protocol/wire-format details, or public-API contracts (`///`) — but keep them
**terse**: state the reason in one or two lines, without spelling out
consequences the reader can derive, restating an already-made point, or
enumerating what the code shows.

This explicitly includes short **in-function** comments that give the business
or protocol reason for a step — e.g. `// Increment zone serial so IXFR
consumers can detect this change` above the serial bump. Keep these mid-body
comments even when the statement itself is obvious: they carry the *why* (which
downstream system or invariant depends on this step), not the *what*. When
trimming verbose comments, do not strip them.

Specifically avoid:

- Trailing scaffolding notes like `id: 0, // Will be set by the database` — the
  placeholder pattern is used throughout and needs no annotation.
- Section labels that echo the code they precede (e.g. `// Table creation
  queries vary by database backend` above the `match self { ... }` that plainly
  does exactly that).

When citing an RFC section, write it out as `RFC 2181, Section 5.2` (and
`Sections 5.2–5.3` for a range) — never the `§` glyph.

`#[allow(dead_code)]` on repository traits and a few facade methods is
deliberate (trait surface consumed across crates / kept to satisfy lints) —
leave it in place.

The same rule applies in tests: the test **name** states *what* behavior is
verified (never restate it in a comment); comments are for *why* the case
exists when that isn't derivable — the regression or protocol rule it guards
(cite the RFC section for wire-format cases), format assumptions the test
relies on, and phase markers in long multi-step e2e flows.

### Test helpers — extraction and visibility

Test code optimizes for standalone readability, not DRY. Extract a helper only
when it hides **mechanics** (how to invoke the CLI, build a config, POST a
request) while the test's meaningful **data and assertions stay inline at the
call site** — and only for blocks that are large or repeated many times and
change in lockstep. Small struct-literal fixtures (`test_record()`-style) stay
local to each test file even when several files have near-identical copies; do
**not** collect them into shared fixture modules.

Import/export rules for helpers that are shared (narrowest visibility that
compiles, never bare `pub`):

1. **Default**: a private `fn` inside the test file that uses it.
2. **Same crate, across modules**: export from the owning module's
   `#[cfg(test)]` tests module with at most `pub(crate)` (e.g.
   `nsupdate/parser/tests.rs::minimal_update_with_ztype`). No crate-wide
   `test_util` grab-bag modules.
3. **e2e suite**: shared helpers live in `tests/common/` as `pub(crate)`
   (`pub(super)` for common-internal ones); the single harness `e2e.rs`
   declares plain private `mod`s. `common/` holds helpers only — test
   functions belong under `api/` / `cli/`.
4. **Never across crates**: no `test-util` features or helper crates;
   duplicate small fixtures per crate instead.

### Clean installs only — no migrations or back-compat

The project targets **clean installs exclusively** and does not support
upgrading an existing deployment. **Do not add migration code, schema
`ALTER`s, schema-version tracking, or shims for older data/config/API
formats** — and remove any that appear. Breaking schema/API/config changes are
fine; change the definition in place.

Schema setup runs `CREATE TABLE/INDEX IF NOT EXISTS` at startup purely for
idempotency (surviving restarts), **not** to migrate existing databases. This
is why MySQL may define indexes inline in `CREATE TABLE` while Postgres/SQLite
use separate `CREATE INDEX` statements — a per-backend syntax requirement, not
a migration step. A reviewer flagging "the inline index won't reach existing
databases" is a non-issue under this policy.

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
