# CLAUDE.md

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

- `bindizr-core` — config, logging, DB models, and the DNS library: value
  types, wire encoding/decoding, DNSSEC signing, TSIG, and zone-file parsing.
  It owns the whole `domain` crate dependency; nothing above it uses `domain`
  directly.
- `bindizr-db` — repository layer. One impl per backend under
  `repository/{mysql,postgres,sqlite}/`. **The three backends are intentionally
  duplicated** (per-backend SQL + error text); do not try to deduplicate them.
- `bindizr-service` — business logic for zones/records (create/update/delete,
  bulk, zone-file import, tokens, serial bumping, RFC 2136 apply).
- `bindizr` — the binary: the daemon runtime (`daemon.rs`) and every front end
  it serves — HTTP API (axum), CLI (clap), Unix-socket daemon IPC, and the DNS
  server (`dns/`: TCP/UDP listeners, AXFR/IXFR/catalog/NOTIFY, nsupdate
  dispatch). The protocol itself lives in core; `dns/` is I/O and dispatch.
- `bindizr-external-dns` — a second binary: the ExternalDNS webhook provider
  adapter, forwarding to bindizr's `/external-dns` API over HTTP. No DNS logic
  or state of its own.
- `bindizr-e2e` — end-to-end API/CLI/DNS tests. Its `[[bin]]` targets exist
  only so `env!("CARGO_BIN_EXE_…")` resolves inside the test package.

## Design rules

### Who decides what

- **Authorization is the service's.** Every service operation a front end can
  reach takes a `Caller` first and gates itself; a transport never calls
  `require_global` on its own. The daemon socket passes `Caller::Global`.
  Service-internal lookups that must skip visibility are `pub(crate)` under
  their own name (`ZoneService::lookup_by_name`). DNS-plane operations
  (transfers, NOTIFY, nsupdate) take no caller — ACL and TSIG authorize there.
- **Transactions are the service's.** No other crate opens one, so `*_tx`
  methods and `RepositoryTx` are `pub(crate)`.
- **A use case has one home.** When two front ends answer the same question,
  the assembly lives in one place both reach (`dns::status::zone_status`,
  shared by the HTTP API and the daemon socket), not once per transport.
- **Payload shapes are the service's.** `bindizr_service::types` is the wire
  contract of the HTTP API, the daemon socket, and the CLI alike; response
  types the CLI reads back derive `Deserialize` too. Front ends convert to
  their own presentation (CLI table rows), never re-derive the payload.

### Transactions and locking

One locking model covers the service layer; keep new code on it:

- A **zone-data mutation** (records, serial, journal rows, versions) is one
  transaction that locks the zone row (`ZoneService::get_by_name_tx` /
  `get_zone_by_name_tx` / `get_zone_tx`, `FOR UPDATE`) **before** any record
  rows — that order is
  the deadlock rule. Authorization, validation, and conflict checks decide on
  rows loaded inside that transaction, never on an earlier unlocked read.
- Outside the transaction belong: pure input parsing/normalization,
  non-locking pre-reads done only to learn the lock target (commented at each
  site), friendly duplicate pre-checks that a UNIQUE/FK constraint backstops,
  and NOTIFY/logging after commit.
- **Reads**: one statement needs no transaction. A derived output that must
  be internally consistent (zone export, version detail, version diff)
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

### Names are labels, not strings

A name is decoded into labels at the parse boundary — `OwnerName::parse_in_zone`
/ `parse_absolute_in_zone`, `ZoneName::parse`, `dns::name::decode_name_labels`
— resolving the `\.`, `\\`, and `\DDD` escapes of RFC 1035, Section 5.1. Every
comparison runs on labels, so a dot inside a label is data, never a boundary.

Do not answer a question about names with string operations. `ends_with`,
`split('.')`, or `strip_suffix` on a name is a bug even when it looks right:
it reads `evil\.example.com` as inside `example.com`. Use `OwnerName`'s
methods (`is_same_or_under`, `is_apex`, `to_fqdn`) or `is_label_suffix`.

Names are canonical by construction: labels are lowercased (RFC 4343) and
rendered back with only `.` and `\` escaped, so one name has one spelling.
That is what lets the record-filter SQL compare owner names as text and
concatenate them into FQDNs.

The row form is the type's, not a caller's: `from_row` decodes it and
`sqlx::Encode` renders it, so bind an `OwnerName` itself rather than a string
you produced. `Display` is the presentation form, whose apex is `@` and not
the empty string a row holds.

`OwnerName::parse_in_zone` qualifies a relative name by appending the zone;
`parse_absolute_in_zone` never does, and is what input carrying no trailing
dot (lookup form, wire owners) must use — otherwise an out-of-zone name is
silently qualified instead of rejected.

Two escapes are unrelated to names and own their own encoding: the SOA RNAME
(`SoaMailbox`, from the admin email) and the TXT value (`TxtRecordValue`,
raw rdata).

### Clean installs only — no migrations or back-compat

The project targets **clean installs exclusively** and does not support
upgrading an existing deployment. **Do not add migration code, schema
`ALTER`s, schema-version tracking, or shims for older data/config/API
formats** — and remove any that appear. Breaking schema/API/config changes are
fine; change the definition in place.

Schema setup runs `CREATE TABLE/INDEX IF NOT EXISTS` at startup for idempotency
across restarts, **not** to migrate existing databases. This is why MySQL may
define indexes inline in `CREATE TABLE` while Postgres/SQLite use separate
`CREATE INDEX` statements — a per-backend syntax requirement, not a migration
step. "The inline index won't reach existing databases" is a non-issue here.

### Only the entry point ends the process

`std::process::exit` belongs in the `execute()` of a binary crate — that
function is the body of `main`, so deciding to stop is its call. Everywhere
else, including `bindizr-core` and `bindizr-db`, report the failure and let it
propagate: a library that exits takes that decision away from whoever embedded
it, and the e2e suite runs both binaries in-process.

## Naming

### Data-access methods — repository traits and the `RepositoryService` facade

A facade method is one SQL call plus error mapping — nothing more. Every
data-access method name is an instance of

```text
<verb>[_many]_<entity>[_by_<keys>][_with_<join>][_<predicate>][_tx]
```

No other segment exists. `_for_<x>` in particular is banned — the grammar has
no slot saying which role `x` plays: if `x` identifies rows it is `_by_<x>`;
if it is a value being written it is just an argument; if it is a condition
it folds into the verb (`upsert`) or the doc comment.

**Verbs are a closed set — do not invent others:**

- `get` — one row by identity; returns `Option`. 404 mapping happens in the
  service layer, never here.
- `list` / `count` — a filtered collection / its cardinality. `list_all` is
  the unfiltered trait form.
- `create` / `update` / `delete` — literal row operations. A partial update
  names the one field it touches: `update_<entity>_<field>`
  (`update_zone_serial_tx`).
- `upsert` — insert-or-update; a conditional rule (the catalog serial
  advancing only when the digest changed) lives in the doc comment, not the
  name.
- `prune` — retention enforcement that may deliberately keep rows the cutoff
  matches (the newest zone version, serial boundaries) — semantics a literal
  `delete_*_older_than` would misdescribe.

`begin_tx` / `finish_tx` / `ping` are transaction/connectivity plumbing, not
entity methods, and are the only exemptions.

**Segments:**

- `_many` / entity — the facade always names the entity, pluralized for batch
  methods (`create_records_tx`); trait methods omit the entity their trait
  already names and mark batch variants `_many`
  (`RecordRepository::create_many_tx`). `_many` never appears in the facade.
- `_by_<keys>` — equality on named columns, joined with `_and_` and never
  dropping `_id` (`list_by_zone_id_and_key_id_tx`). The entity's canonical id
  keys are elided, carried by the signature alone: bare `get`/`update`/
  `delete` take the row's own id, bare `list`/`count` the owning zone's id
  (`list_all` stays the unfiltered form). A non-id selector is always named,
  the canonical scope still elided around it (`get_by_serial(zone_id,
  serial)`, `list_by_name_tx(tx, zone_id, name)`). Every other key path is
  spelled in full: a non-canonical side (`list_by_token_id`,
  `count_by_key_id`, `delete_by_zone_id_tx`), a batch over many scopes
  (`list_by_zone_ids`), and any key set whose elision would leave two methods
  of one surface distinguishable only by their signatures — which is why the
  two-sided policy tables spell everything.
- `_with_<join>` — the result carries joined data
  (`get_record_with_zone`); never a filter or semi-join.
- `_<predicate>` — a comparison filter as `<subject>_<comparison>`. Serial
  intervals keep their contracts in doc comments — the journal's
  `between_serials` is the IXFR half-open `(from, to]`, the versions'
  `in_serial_range` the closed `[from, to]`.
- Projections — a method returning one column rather than entity rows names
  that column, pluralized, where the rows would be
  (`list_zone_ids_expiring_before`); the facade prefixes the row set being
  filtered (`list_rrsig_zone_ids_expiring_before` — `rrsig`, since only
  RRSIG rows carry `expires_at`).
- `_tx` — runs on the caller's transaction, taken as the first parameter.

**Time filters** take a `cutoff` parameter and resolve the predicate's
subject one of three ways, most specific first:

- bound to the preceding `_by_` value when the timestamp records entry into
  the selected state: `list_by_state_entered_before` (`state_changed_at`);
- the row's own timestamp column, verb-formed: `expiring_before`
  (`expires_at`);
- elided for the row's own age: `older_than` (`created_at`) — the `prune`
  retention form.

Never spell a raw column name into the predicate (`state_changed_before`):
it reads as a bare column filter and hides that the state itself is an
equality selector the name must carry as `_by_state`.

### Service methods

- `XxxService` methods carry the domain semantics and omit the entity the
  struct already names (`ZoneService::get_by_name`, not `get_zone_by_name`).
  Verbs: `get_*` maps a miss to NotFound, `find_*` returns `Option`, `list_*`
  returns a collection, `count_*` a count; a domain verb is preferred where
  it says more (`advance_catalog_serial`, `sign_zone_tx`).
- A record mutation that also writes IXFR journal rows says so in the name:
  `*_with_changes_tx`. Preconditions (e.g. "caller already validated the
  rows") belong in the doc comment, not the name.
- Adjacent layers never reuse one name for different semantics (e.g. a raw
  row delete in the facade vs. a delete-plus-journal-log in the service).

### Free-function helpers

The `get_*`/`find_*`/`list_*`/`count_*` verbs above are reserved for data
access and mean the same thing in every crate, not just the service — a free
helper that computes a value never takes `get_`. Other helper verbs:

- `to_<form>` — convert a name/value into a named form (`to_fqdn_lowercase`,
  `to_lookup_name`).
- `encode_<thing>` — a typed value into its wire bytes (`encode_name`).
- `parse_<thing>` — text or wire bytes into a typed value.
- `classify_<thing>` — check returning core's typed `ParseNameError`, with no
  field context; `validate_<thing>` is the same check phrased against a named
  field and mapped to the caller's error type. The pair lives together.
- `normalize_<thing>` — service-layer trim + canonicalize + validate,
  returning the canonical value or a `ServiceError`.
- `is_<x>` / `has_<x>` — predicates.

One concept keeps one name across crates. Do not add a wrapper that only
reorders or renames the arguments of the function it calls — call it directly.

## Code style

### Comments

Keep comments that explain **why**: non-obvious behavior or invariants,
protocol/wire-format details, public-API contracts (`///`). State the reason in
one or two lines, without spelling out consequences the reader can derive,
restating an already-made point, or enumerating what the code shows.

This includes short **in-function** comments giving the business or protocol
reason for a step — e.g. `// Increment zone serial so IXFR consumers can detect
this change`. Keep them even when the statement is obvious: they carry which
downstream system or invariant depends on the step. Do not strip them when
trimming.

The same applies in tests: the test **name** states *what* is verified (never
restate it in a comment); comments are for *why* the case exists when that
isn't derivable — the regression or protocol rule it guards (cite the RFC
section for wire-format cases), format assumptions the test relies on, and
phase markers in long multi-step e2e flows.

Specifically avoid:

- Trailing scaffolding notes like `id: 0, // Will be set by the database` — the
  placeholder pattern is used throughout and needs no annotation.
- Section labels that echo the code they precede (e.g. `// Table creation
  queries vary by database backend` above the `match self { ... }` that plainly
  does exactly that).
- Change-history / changelog notes (`// previously used a date-based serial`,
  `// changed in v2`, `// no longer needed`) — that belongs in commit history.

Cite RFC sections as `RFC 2181, Section 5.2` (`Sections 5.2–5.3` for a range),
never the `§` glyph.

### No dead code, no `#[allow(dead_code)]`

The workspace builds warning-free with no `#[allow(dead_code)]` anywhere; keep
it that way. Repository traits and the `RepositoryService` facade carry only
methods with a live caller — do **not** add one "for symmetry" with an existing
`_tx`/non-`_tx` pair or to round out a trait's surface.

The traits are `pub` and consumed across crates, so rustc cannot see when
removing a facade method orphans the trait method beneath it. After deleting
anything from the facade, re-check the layer below: a dead facade method, its
trait declaration, and its three backend impls all go together.

### Module file layout — `mod.rs`, never the sibling form

A module with submodules is a directory containing `mod.rs`
(`bindizr-core/src/dns/message/mod.rs`), not the 2018-edition sibling form
(`message.rs`
next to `wire/`). The community leans the other way, so the uniformity is
deliberate — do not "modernize" it.

Unit tests usually drive this: small ones stay inline as `#[cfg(test)] mod
tests { … }`, larger ones move to `<module>/tests.rs` declared from `mod.rs`.

### Visibility records usage

Items and struct fields carry the narrowest visibility that compiles: `pub`
means another crate touches it today, `pub(crate)` that only its own crate
does. A struct mixing the two is a measurement, not a design statement — widen
a field when the compiler asks, and no sooner. This keeps rustc's dead-code
analysis covering fields (`pub` fields are exempt) and keeps cross-crate struct
literals impossible.

Deliberate exceptions: `bindizr_service::types` payloads are fully `pub` (their
fields are the wire contract), and invariant-bearing types (`OwnerName`) keep
fields private behind constructors.

### Helper extraction — split at the second caller

Do not pre-split a function for a caller that has not arrived: extract the
shared helper when the second caller appears (`validate_rrset_shape` left
`convert_rrset` only when `adjust_rrset` needed it too). A single-caller
helper is justified by its contract, never by call count: the name plus a
narrow signature must let the caller be read without opening the body
(`normalize_ttl`). A name that merely labels a section of its one caller, or
a body correct only next to that caller's invariants, belongs inlined — long
sequenced bodies (`apply_changes`) stay whole rather than fragmented.

### Test helpers — extraction and visibility

Test code optimizes for standalone readability, not DRY. Extract a helper only
when it hides **mechanics** (how to invoke the CLI, build a config, POST a
request) while the test's meaningful **data and assertions stay inline at the
call site** — and only for blocks that are large or repeated many times and
change in lockstep. Small struct-literal fixtures (`test_record()`-style) stay
local to each test file even when several files have near-identical copies; do
**not** collect them into shared fixture modules.

Import/export rules for shared helpers (narrowest visibility that compiles,
never bare `pub`):

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

## Generated artifacts & documentation

### OpenAPI spec — generated only, never hand-edited

`docs/openapi.yaml` is a build artifact generated by utoipa — **never edit it
by hand**. The source of truth is the `#[utoipa::path]` annotations and the
schema types registered in `crates/bindizr/src/api/openapi.rs`. To change the
spec, change the annotations, then regenerate the file from a bindizr serving
the document (`api.openapi_enabled = true`, off by default since it describes
the whole API surface):

```sh
bindizr start -c <config> &   # config with api.openapi_enabled = true
curl -s http://127.0.0.1:<api_port>/openapi.yaml > docs/openapi.yaml
```

Pages CI rebuilds the hosted API docs when `docs/openapi.yaml` changes on
`main`.

### Documentation site

`docs/` is the MkDocs Material source for
<https://kweonminsung.github.io/bindizr/>, configured by `mkdocs.yml` and
deployed by `.github/workflows/update-github-pages.yml` on pushes to `main`.
The workflow uploads `site/` straight to Pages — no rendered HTML is committed,
and the Pages source must stay on **GitHub Actions**, not "deploy from a
branch". `docs/openapi.yaml` is the one committed generated artifact, per the
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

Every run writes to its own timestamped directory
**`results_<YYYYmmdd_HHMMSS>/`** (e.g. `results_20260710_233856/`), created in
[`benchmarks/lib/settings.py`](benchmarks/lib/settings.py). This is the single
canonical naming convention — never refer to a bare `results/` directory in
code, docs, or messages. Set `BENCH_RESULTS_DIR` to reuse an existing directory
when re-running a subset (`-b ...`) so the report is rebuilt from the full raw
set. Results (`performance.{md,csv,json}` + `graphs/`) and the `results_*/`
dirs are git-ignored.
