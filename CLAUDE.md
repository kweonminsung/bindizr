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
- `bindizr-external-dns` — a second binary: the ExternalDNS webhook provider
  adapter. It speaks the webhook protocol and forwards to bindizr's
  `/external-dns` API over HTTP; no DNS logic or state of its own.
- `bindizr-e2e` — end-to-end API/CLI/DNS tests. Its `[[bin]]` targets exist
  only so `env!("CARGO_BIN_EXE_…")` resolves inside the test package.

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
- Change-history / changelog notes (`// previously used a date-based serial`,
  `// changed in v2`, `// no longer needed`) — why a value changed belongs in the
  commit history, not the source.

When citing an RFC section, write it out as `RFC 2181, Section 5.2` (and
`Sections 5.2–5.3` for a range) — never the `§` glyph.

### No dead code, no `#[allow(dead_code)]`

The workspace builds warning-free with no `#[allow(dead_code)]` anywhere; keep
it that way. Repository traits and the `RepositoryService` facade carry only
methods with a live caller — do **not** add a method "for symmetry" with an
existing `_tx`/non-`_tx` pair or to round out a trait's surface.

Because the traits are `pub` and consumed across crates, rustc cannot see when
a facade method's removal orphans the trait method beneath it. After deleting
anything from the facade, re-check the layer below: a dead facade method,
its trait declaration, and its three backend impls all go together.

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

### Transactions and locking

One locking model covers the service layer; keep new code on it:

- A **zone-data mutation** (records, serial, IXFR changes, snapshots) is one
  transaction that locks the zone row (`ZoneService::get_by_name_tx` /
  `get_zone_by_*_tx`, `FOR UPDATE`) **before** any record rows — that order is
  the deadlock rule. Authorization, validation, and conflict checks decide on
  rows loaded inside that transaction, never on an earlier unlocked read.
- Outside the transaction belong: pure input parsing/normalization,
  non-locking pre-reads done only to learn the lock target (commented at each
  site), friendly duplicate pre-checks that a UNIQUE/FK constraint backstops,
  and NOTIFY/logging after commit.
- **Reads**: one statement needs no transaction. A derived output that must
  be internally consistent (zone export, snapshot detail, snapshot diff)
  takes a transaction plus the zone lock. Paginated listings run count and
  page as plain statements; drift between the two is accepted.
- **Single-statement management writes** (tokens, TSIG keys, policies) take
  no transaction: UNIQUE/FK constraints backstop their check-then-act races,
  mapped to friendly errors in the repository facade.
- Isolation is pinned to READ COMMITTED on every backend; correctness comes
  from row locks and constraints, never from snapshot isolation. The
  ExternalDNS apply resolves authoritative zones from committed state inside
  its transaction; the residual race with concurrent zone creation is
  accepted.

### Service / repository naming

- `RepositoryService` methods are one SQL call plus error mapping — nothing
  more. They always name the entity, as
  `<verb>_<entity>[_by_<key>][_with_<join>][_tx]`
  (`get_zone_by_name_tx`); `get_*` returns `Option` — 404 mapping happens in
  the service layer, never here.
- `XxxService` methods carry the domain semantics and omit the entity the
  struct already names (`ZoneService::get_by_name`, not `get_zone_by_name`).
  Verbs: `get_*` maps a miss to NotFound, `find_*` returns `Option`, `list_*`
  returns a collection, `count_*` a count.
- `_tx` means the function runs on the caller's transaction and takes `tx` as
  its first parameter.
- A record mutation that also writes IXFR zone changes says so in the name:
  `*_with_changes_tx`. Preconditions (e.g. "caller already validated the
  rows") belong in the doc comment, not the name.
- Adjacent layers never reuse one name for different semantics (e.g. a raw
  row delete in the facade vs. a delete-plus-IXFR-log in the service).

### Only the entry point ends the process

`std::process::exit` belongs in the `execute()` of a binary crate — that
function is the body of `main`, so deciding to stop is its call. Everywhere
else, including `bindizr-core` and `bindizr-db`, report the failure and let
it propagate; a library that exits takes that decision away from whoever
embedded it, and the e2e suite runs both binaries in-process.

### Names are labels, not strings

A name is decoded into labels at the parse boundary — `OwnerName::parse_in_zone`
/ `parse_absolute_in_zone`, `ZoneName::parse`, `dns::name::decode_name_labels`
— resolving the `\.`, `\\`, and `\DDD` escapes of RFC 1035, Section 5.1. Every
comparison runs on labels, so a dot inside a label is data, never a boundary.

Do not answer a question about names with string operations. `ends_with`,
`split('.')`, or `strip_suffix` on a name is a bug even when it looks right:
it reads `evil\.example.com` as inside `example.com`. Use `OwnerName`'s
methods (`is_same_or_under`, `is_apex`, `to_fqdn`) or `labels_in_zone`.

Names are canonical by construction: labels are lowercased (RFC 4343) and
rendered back with only `.` and `\` escaped, so one name has one spelling.
That is what lets the record-filter SQL compare owner names as text and
concatenate them into FQDNs. Rows hold that presentation string;
`OwnerName::from_row` decodes it.

`OwnerName::parse_in_zone` qualifies a relative name by appending the zone;
`parse_absolute_in_zone` never does, and is what input carrying no trailing
dot (lookup form, wire owners) must use — otherwise an out-of-zone name is
silently qualified instead of rejected.

Two escapes are unrelated to names and own their own encoding: the SOA RNAME
(`SoaMailbox`, from the admin email) and TXT rdata (`TxtRdata`).

### Free-function helper naming

The `get_*`/`find_*`/`list_*`/`count_*` verbs above are reserved for data
access and mean the same thing in every crate, not just the service — a free
helper that computes a value never takes `get_`. Other helper verbs:

- `to_<form>` — convert a name/value into a named form (`to_fqdn_lowercase`,
  `to_encoded_owner_name`).
- `parse_<thing>` — text or wire bytes into a typed value.
- `classify_<thing>` — check returning core's typed `ParseNameError`, with no
  field context; `validate_<thing>` is the same check phrased against a named
  field and mapped to the caller's error type. The pair lives together.
- `normalize_<thing>` — service-layer trim + canonicalize + validate,
  returning the canonical value or a `ServiceError`.
- `is_<x>` / `has_<x>` — predicates.

One concept keeps one name across crates. Do not add a wrapper that only
reorders or renames the arguments of the function it calls — call it directly.

### OpenAPI spec — generated only, never hand-edited

`docs/openapi.yaml` is a build artifact generated by utoipa — **never edit it
by hand**. The source of truth is the `#[utoipa::path]` annotations and the
schema types registered in `crates/bindizr/src/api/openapi.rs`. To change the
spec, change the annotations, then regenerate the file from a **debug** build
(the OpenAPI endpoints are debug-only):

```sh
bindizr start -c <config> &   # debug build
curl -s http://127.0.0.1:<api_port>/openapi.yaml > docs/openapi.yaml
```

Pages CI rebuilds the hosted API docs when `docs/openapi.yaml` changes on
`main`.

### Documentation site

`docs/` is the MkDocs Material source for
<https://kweonminsung.github.io/bindizr/>, configured by `mkdocs.yml` and
deployed by `.github/workflows/update-github-pages.yml` on pushes to `main`.
No rendered HTML is committed any more — the workflow uploads `site/` straight
to Pages (Pages source must stay on **GitHub Actions**, not "deploy from a
branch"). `docs/openapi.yaml` is still a committed generated artifact, per the
section above.

- Build locally with
  `uv run --with-requirements docs/requirements.txt mkdocs serve`. CI runs
  `mkdocs build --strict`, so a broken internal link fails the build.
- `docs/requirements.txt` pins mkdocs and mkdocs-material exactly; it lives in
  `docs_dir` and is kept out of the site by `exclude_docs` in `mkdocs.yml`.
- Images live in `docs/assets/`, referenced as `assets/…` from docs pages and as
  `docs/assets/…` from the README. There is no second copy.
- The Redoc API reference is rendered into `site/api/` by the same workflow, so
  the MkDocs nav links to it absolutely instead of owning a page. Do not add a
  `docs/api/` directory — it would collide.
- README.md is a landing page (pitch, quickstart, links into the site), not a
  manual. New prose belongs in `docs/`.

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
