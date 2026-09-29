# CLAUDE.md

## Overview

Bindizr is a Rust DNS control plane for authoritative name servers (BIND,
Knot DNS, NSD, PowerDNS). It manages zones/records via an HTTP API or CLI,
stores them in MySQL / PostgreSQL / SQLite, and propagates changes to the
secondaries via AXFR/IXFR using DNS Catalog Zones (RFC 9432).
It also serves RFC 2136 dynamic updates (nsupdate).

## Build / Test / Lint

```bash
cargo build -p bindizr                                    # build the binary
cargo build --workspace                                   # build everything
cargo test --workspace --all-features -- --test-threads=1 # full suite (CI cmd)
cargo clippy --workspace                                  # lint
cargo +nightly fmt                                         # format (needs nightly)
```

- Tests run single-threaded: `.cargo/config.toml` sets `RUST_TEST_THREADS=1`,
  so plain `cargo test` complies; the explicit `--test-threads=1` in the CI
  command is the same guarantee spelled out.
- `rustfmt.toml` enables unstable features (`imports_granularity`,
  `group_imports`), so formatting requires the **nightly** toolchain. On stable
  `cargo fmt` runs but silently ignores those options.
- `bindizr-e2e` uses temporary SQLite databases and local processes by default.
  Set `BINDIZR_E2E_VERIFY_DNS=true` to run against DB/BIND9 containers with Docker
  (also set `BINDIZR_E2E_ARM=true` on ARM). The other crates' `--lib` tests run
  without external services.

## Architecture — workspace crates

- `bindizr-core` — config, logging, DB models, and the DNS library: value
  types, wire encoding/decoding, DNSSEC signing, TSIG, and zone-file parsing.
  It owns the whole `domain` crate dependency; nothing above it uses `domain`
  directly.
- `bindizr-db` — data access behind a `Db` value: `Db::connect` returns an
  enum over the three sqlx pools, and `db.begin()` a `Transaction` enum
  over their transactions. One module per entity at the crate root
  (`bindizr_db::zone`), whose functions take the `Db` or the `Transaction`
  first and match its backend to call the same-named function in `mysql/`,
  `postgres/`, or `sqlite/`, where the SQL lives. **The three backends are
  intentionally duplicated** (per-backend SQL + error text); do not try to
  deduplicate them.
- `bindizr-service` — business logic for zones/records (create/update/delete,
  bulk, zone-file import, tokens, serial bumping, RFC 2136 apply), plus the
  outbound DNS clients its flows drive (`dns_client/`: NOTIFY fan-out, SOA
  probing, parent-DS probing, inbound AXFR) — the wire format stays core's.
  `transfer` records what the DNS server served each client, in the
  database, so a secondary's transfers read back across restarts. It owns
  `Context`, the daemon's state — configuration, `Db`, metrics, the NOTIFY
  and scheduler senders — which every service function takes first.
- `bindizr` — the binary: the daemon runtime (`daemon/`: `bootstrap` builds
  the `Context` in dependency order and serves it) and every front end
  it serves — HTTP API (axum), CLI (clap), Unix-socket daemon IPC, and the DNS
  **server** (`dns/`: TCP/UDP listeners, AXFR/IXFR/catalog/NOTIFY serving,
  nsupdate dispatch). The protocol itself lives in core, outbound clients in
  the service; `dns/` is inbound I/O and dispatch.
- `bindizr-external-dns` — a second binary: the ExternalDNS webhook provider
  adapter, forwarding to bindizr's `/external-dns` API over HTTP. No DNS logic
  or state of its own.
- `bindizr-e2e` — end-to-end API/CLI/DNS tests. Its `[[bin]]` targets exist
  only so `env!("CARGO_BIN_EXE_…")` resolves inside the test package.

## Design rules

### Rust idioms — a module is the namespace, an enum the closed set, a type the error

The [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
settle what this file does not; a checklist tag beside a rule
(`C-GOOD-ERR`) names the item it rests on. The shapes below are the ones a
reader coming from Java reaches for by reflex and Rust spells differently;
each rule says which spelling is this project's.

- **A module is the namespace.** A unit struct whose `impl` holds only
  associated functions (`pub struct ZoneService; impl ZoneService { pub
  async fn create(…) }`) is a module spelled as a class, and does not exist
  here: `bindizr_service::zone` is a module of functions, and a front end
  imports the module and calls `zone::create(&cx, &caller, &request)`. The
  entity is the module's name, so a function omits it (`zone::get_by_name`,
  never `zone::get_zone_by_name`). A module that spreads over files by verb
  (`zone/create.rs`, `zone/get.rs`) declares them in `mod.rs` and
  re-exports their functions flat (`pub use create::create;`), so the path
  a caller writes is `zone::create` — the shape of `tokio::fs::read` — and
  a sibling reaches a sibling by that same path (`super::lookup_by_name`),
  never `Self::`. An HTTP route group is the same: `api::zone::routes()` is
  a function, not `ZoneApi::routes()`. A struct exists where there is a
  value — fields, or an invariant behind them — and its methods take
  `self` (`C-METHOD`): `Caller`, `OwnerName`, `DnsMessageBuilder`,
  `Metrics`.
- **A closed set is an enum; a trait is for an open one.** The process
  chooses one of three database backends at startup and never another, so
  the backend is `enum DatabasePool { MySql(…), Postgres(…), Sqlite(…) }`
  and the code that differs per backend is a `match` on it, in a function
  per query (`bindizr_db::zone::get_by_name`) that calls the same-named
  backend function where the SQL lives. A trait with three implementors
  that nothing names generically — no `T: ZoneRepository` bound, no test
  double, since a test builds a `Context` over in-memory SQLite — is an
  interface in the Java sense: it exists only to be boxed,
  and `Box<dyn ZoneRepository>` from a factory adds a heap allocation, a
  vtable and a `pool.clone()` to every query to reach a backend the enum
  already knows. A trait is declared when its implementors are open (a
  caller outside the crate may add one) or a generic bound needs it
  (`impl IntoIterator<Item = &Record>`); one whose implementors all live
  in one crate and are only ever boxed is an enum. The transaction
  follows: `Transaction<'a>` is an enum a `_tx` function matches, so a
  backend function receives its own `sqlx::Transaction` and no "kind
  mismatch" error can exist. Nothing needs `async-trait`.
- **An error is a type** (`C-GOOD-ERR`). Every fallible function returns
  a `Result` whose error is a type declared in the module that raises it,
  derived with `thiserror`, implementing `std::error::Error` with its
  `source()` intact, `Send + Sync`, its `Display` lowercase without a
  trailing period, named `<Verb><Object>Error` (`ParseNameError`,
  `C-WORD-ORDER`) or `<Layer>Error` for a layer's whole surface
  (`DatabaseError`, `ServiceError`). `String` is never an error type — not
  `Result<T, String>`, not `type Err = String`, not an `Option<String>`
  holding the reason — and no error type implements `From<String>` or
  `From<&str>`: that impl is the sink a stringly error drains into. A
  variant is what a caller can match on; the site's detail (a name, a
  value) is a field of it. Crossing a layer is a `From` impl and `?`
  (`From<DatabaseError> for ServiceError`), never a `map_err(|e|
  ServiceError::internal(format!("failed to …: {}", e)))` that flattens
  the source to text; `map_err` appears where the site adds a
  classification the source cannot (a UNIQUE violation read as
  `zone_conflict`). `ServiceError` is an enum whose variants are its
  `ErrorCode`s, each carrying the message the error payload shows — the
  wire fixes that text, so a variant holds it rather than typed fields —
  and the two server-fault variants (`Internal`, `DnssecSigningFailed`)
  keep the failure beneath them as their `source`. `code()` and `Display`
  are the two faces the payload reads, and it knows nothing of HTTP: a
  front end maps a code to its own status (`api/error.rs` to an HTTP
  status, `cli/error.rs` to an exit code, the nsupdate server to an RCODE)
  and asks the service only what it can answer (`is_internal()`). A layer
  above the service names its own type the same way (`DaemonError`,
  `XfrError`, `CliError`), with `From` impls for what it wraps. An error of
  the `domain` crate is carried boxed (`dns::LibraryError`): its types vary
  across versions and nothing here matches on them; the few that implement
  no `Error` at all (`SigningError`, `TxtError`) keep their text in a
  `reason` field, which is the one place a message stands in for a source.
  `unwrap` and `expect` never stand in for a `Result`: an error that a
  static definition makes impossible still travels as a type
  (`Metrics::new` returns `RegisterMetricsError`), a `Result` whose error
  is `Infallible` is read with `let Ok(()) = …`, an invariant the code can
  restructure around is restructured (the lock target an update pre-reads
  is an enum, not an `Option` unwrapped later), and the `expect`s that
  remain guard a constructor's own invariant, a poisoned lock, or a foreign
  builder's limit a single question cannot reach.
- **Conversions are the standard traits** (`C-CONV-TRAITS`, `C-CTOR`,
  `C-CONV`). A value derived from one other value and nothing else is
  `impl From<&Zone> for GetZoneResponse` (`TryFrom` when it can fail),
  which is how `cli/output/table.rs` already builds every row; a named
  `from_<source>` constructor exists only where `From` cannot say it — an
  extra argument (`from_secondary(secondary, notify_key_name)`), or an
  encoding the type name does not fix (`OwnerName::from_row`,
  `SoaMailbox::from_email`). `Into` and `TryInto` are never implemented.
  The prefix says the cost: `as_` borrows for free, `to_` does work and
  returns an owned value, `into_` consumes `self`. A conversion trait is
  implemented for a type, never for a `Result` — the caller writes `?`
  first.
- **A constructor is an associated function named by how the value comes
  to be** (`C-CTOR`): `new` for the plain case, with `Default` beside it
  when there is a no-argument form; `connect`, `load`, `spawn` for one that
  does I/O or starts work (`Db::connect`, `Config::load`,
  `NotifyQueue::spawn`); `from_<source>` for the conversions above. A
  builder (`DnsMessageBuilder`) exists where construction is incremental;
  a struct of optional fields with `Default` and update syntax
  (`ZoneFilter { name, ..Default::default() }`) is the plain form, not a
  builder (`C-BUILDER`).
- **An argument carries its meaning in its type** (`C-CUSTOM-TYPE`,
  `C-NEWTYPE`). A `bool` parameter states a fact the field is named by
  (`enabled: bool` being written, `incremental: bool` stored on the
  transfer row); a `bool` that selects what the function does is a
  two-variant enum named for the choice — `Run::DryRun`, `ZoneView::Signed`,
  `DsCheck::Skip`, `Holddown::Skip`, `NotifySerial::Bump`,
  `VersionScope::All`, `SigningPass::Full` — so `zone::delete(&cx, &caller,
  &name, Run::DryRun)` reads without the signature, and several such
  choices on one call are one struct of named fields. The front end that
  parses the flag builds the enum (`Run::from_dry_run(dry_run)`) and the
  socket carries it as such. An `Option<&str>` that means "all" when
  `None` is an enum with an `All` variant (`NotifyTarget::All`); an
  `Option<&str>` that spells an enum (`role`, `algorithm`) is parsed to
  that enum by the front end — parse at the boundary, pass the type. A
  policy *name* stays a string: it names a row, not a variant. A number
  with a meaning of its own is a newtype: `Serial`, `Ttl` and
  `SoaInterval` in `bindizr_core::dns`, `KeyTag` in `dns::dnssec`, the
  policy's `Days`, each with its `i32` row form and its wire or payload
  form (`u32`, `u16`) as `From`/`TryFrom` conversions and its own sqlx
  encoding, and an entity's row id beside its row (`ZoneId`, `RecordId`,
  `TokenId`, …, one `id_newtype!` each), so `list_by_zone_id_and_key_id_tx(
  tx, key_id, zone_id)` no longer compiles. A payload keeps its wire schema
  through `#[schema(value_type = …)]`; a request's raw `i32`/`u32` field is
  validated into the newtype by the service (`validate_record_ttl`,
  `validate_initial_serial`, `normalize_soa_interval`). A record's
  priority stays `Option<i32>` up to the value parser: `RecordType` reads
  it with the value and phrases its range against the type (`MX
  priority`), so no earlier type could carry it. A cast that loses nothing
  is a `From` (`i64::from(count)`); the `as` casts that remain truncate or
  change sign on purpose.
- **Common traits, eagerly** (`C-COMMON-TRAITS`, `C-DEBUG`). Every type
  derives `Debug`; `Clone` unless it owns a resource; `PartialEq, Eq` when
  its fields allow; `Copy` for a fieldless enum or a small plain struct;
  `Hash` and `Ord` when it keys a map or sorts; `Default` when the empty
  value means something (a filter); `Serialize` / `Deserialize` on every
  payload — a row carries neither, since nothing serializes one and two
  hold secrets. A fixed set keeps `as_str` and `Display` as
  *Presentation* says.
- **Casing is RFC 430** (`C-CASE`): an acronym is one word — `MySql`,
  `Postgres`, `Sqlite`, `Tsig`, `Dnssec` — and no lint is allowed away to
  hide an exception. A protocol token keeps its own spelling only inside a
  string (`"AXFR"`).
- **A protocol message is a data-carrying enum.** The daemon socket's
  command is one `enum DaemonCommand` whose variants carry their payload
  (`UpdateZone { zone_name, request }`), serialized as
  `#[serde(tag = "command", content = "data")]`, and the server `match`es
  it straight into typed data; a unit-variant kind beside a
  `serde_json::Value` that a `parse_params` step re-types is one message
  described twice.
- **State is a value, passed by reference.** Every service function takes
  the `Context` first (`zone::create(&cx, &caller, &request)`), the way
  cargo's `ops` take their `GlobalContext`; an axum handler receives it as
  `State<Arc<Context>>`, a spawned task holds an `Arc<Context>`. No
  function reaches for a `static` to find the configuration, the pool, the
  metrics, or a cache: *State is a value* says what the `Context` holds,
  what a front end holds for itself, and which two globals remain. A test
  that needs a database builds its own `Context` over an in-memory SQLite
  `Db` — what explicit state buys, and why nothing is mocked.

### Who decides what

- **Authorization is the service's.** Every service operation a front end can
  reach takes the `Context` first, a `Caller` next, and gates itself; a
  transport never calls
  `authorize_global` on its own. The daemon socket passes `Caller::Global`.
  Service-internal lookups that must skip visibility are `pub(crate)` under
  their own name (`zone::lookup_by_name`). The daemon socket
  authenticates its peer by uid (`peer_cred` on both ends: the daemon's own
  user or root); the socket's file mode is a courtesy, not the boundary.
  DNS-plane operations
  (transfers, NOTIFY, nsupdate) take no caller — ACL and TSIG authorize there.
  So do operations with nothing to gate: pure request normalization
  (`external_dns::adjust_records`), a token reading itself
  (`token::grant::list_self`, keyed by the authenticated `ApiToken`), and
  the aggregate counts behind the unauthenticated metrics endpoint
  (`count_all`), which expose no zone data.
- **Transactions are the service's.** No other crate opens one: `Db` is a
  private field of `Context`, read by `cx.db()` inside the service crate
  alone, so the service's `*_tx` functions and its `Transaction` re-export
  are `pub(crate)`.
- **A use case has one home.** When two front ends answer the same question,
  the assembly lives in one place both reach (`zone::get_status`,
  shared by the HTTP API and the daemon socket), not once per transport.
- **Payload shapes are the service's.** `bindizr_service::types` is the wire
  contract of the HTTP API, the daemon socket, and the CLI alike; response
  types the CLI reads back derive `Deserialize` too. Front ends convert to
  their own presentation (CLI table rows), never re-derive the payload.
  One vocabulary across payloads: a field that names another entity is
  `<entity>_name` (`zone_name`, `token_name`, `notify_key_name`,
  `policy_name`), a serial is `u32`, a key tag `u16`, a count `u64` named
  `added`/`deleted`/`unchanged` (a diff says `removed`), a fixed set of
  values is an enum with a schema — `*Result` for how one attempt turned
  out (`TransferResult`, the metrics `XfrResult`), `*Status` for what a
  check finds (`SecondaryStatus`, `DoctorCheckStatus`, `HealthStatus`),
  `*State` for where a thing stands in its lifecycle (`DnssecKeyState`,
  `DsState`) — whose failure variant is `Failed` and never `Error` or
  `Fail`, so that `error` stays the text beside it, and a response's
  `Option` is emitted as `null`, never
  skipped, so clients read one shape. One entity travels in an envelope
  keyed by its name (`{"zone": …}`); a report (status, check, diff, import,
  rollback, the DNSSEC status) travels bare. A listing's query parameters
  come from its filter struct (`IntoParams`), never a hand-written list.

### Transactions and locking

One locking model covers the service layer; keep new code on it:

- A **zone-data mutation** (records, serial, journal rows, versions) is one
  transaction that locks the zone row (`zone::get_by_name_tx` in the
  service, `bindizr_db::zone::get_by_name_tx` / `get_tx` beneath it,
  `FOR UPDATE`) **before** any record rows — that order is the deadlock
  rule. Authorization, validation, and conflict checks decide on
  rows loaded inside that transaction, never on an earlier unlocked read.
  `get_by_name_tx` is the unchecked tx lookup (record writes authorize
  through `authorize_record_writes_tx`); the caller-gated tx read is
  `get_visible_by_name_tx`.
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
  read as friendly conflicts where the service calls the statement.
- Isolation is pinned to READ COMMITTED on every backend; correctness comes
  from row locks and constraints, never from snapshot isolation. The
  ExternalDNS apply resolves authoritative zones from committed state inside
  its transaction; the residual race with concurrent zone creation is
  accepted.
- **The row lock and the constraint are the whole guarantee.** The service
  layer never re-guards the gap between an unlocked pre-read and the locked
  read after it: no fingerprint or "changed meanwhile" comparison, no
  snapshot carried across a network wait, no in-process mutex or
  singleflight around a cache miss. Such a guard means something only if
  every path carries it, and none does. Work whose answer the transaction
  acts on — a parent-DS probe included — runs inside it under the zone
  lock; a read-only path runs it outside and accepts drift. The duplicate
  pre-check above is an integrity check the constraint backstops, not a
  concurrency guard.

### Names are labels, not strings

A name is decoded into labels at the parse boundary — `OwnerName::parse_in_zone`
/ `parse_absolute_in_zone`, `ZoneName::parse`, `dns::name::decode_name_labels`
— resolving the `\.`, `\\`, and `\DDD` escapes of RFC 1035, Section 5.1. Every
comparison runs on labels, so a dot inside a label is data, never a boundary.

Do not answer a question about names with string operations. `ends_with`,
`split('.')`, or `strip_suffix` on a name is a bug even when it looks right:
it reads `evil\.example.com` as inside `example.com`. Use `OwnerName`'s
methods (`is_same_or_under`, `is_apex`, `to_fqdn`) or `is_label_suffix`.

Names are canonical by construction: labels are printable ASCII (an
internationalized label arrives as its `xn--` A-label), lowercased
(RFC 4343), and rendered back with the in-label dot as `\046` and the
master-file metacharacters escaped, so one name has one spelling and a `.`
in rendered text is always a label boundary. That is what lets the
record-filter SQL compare owner names as text under a bytewise collation,
match a grant's subtree with `LIKE`, and concatenate them into FQDNs.

The row form is the type's, not a caller's: `from_row` decodes it and
`sqlx::Encode` renders it, so bind an `OwnerName` itself rather than a string
you produced. `Display` is the presentation form, whose apex is `@` and not
the empty string a row holds. A `ZoneName` and a secondary's `AddressTarget`
(`host:port`, the port spelled out and the host lowercase) are rows the same
way: parsed once by the service, bound as themselves, and read back typed,
so nothing splits or re-parses their text at the point of use.

`OwnerName::parse_in_zone` qualifies a relative name by appending the zone;
`parse_absolute_in_zone` never does, and is what input carrying no trailing
dot (lookup form, wire owners) must use — otherwise an out-of-zone name is
silently qualified instead of rejected.

A zone name crosses into the service as a `ZoneName`, parsed where its text
arrives by `zone::normalize_name`, which owns the request-phrased rejection
(`INVALID_ZONE_FIELD`; the root and a wildcard refused): an HTTP path or
query parameter in its handler, a socket command in its handler, a transfer
question in the DNS server once the catalog check has passed. A name inside
a request body or a listing filter is parsed by the service function that
takes that payload, since the payload is its argument. Everything beneath —
the `_tx` lookups, the NOTIFY and probe clients, the zone-file parser, the
db layer, which binds a `ZoneName` as it binds an `OwnerName` — takes
`&ZoneName` and parses nothing again, and `dns.catalog_zone_name` is a
`ZoneName` from the moment the configuration loads. The transfer log's
`save_refused` and `save_failed` alone take the question's text, because a
refusal may come before any parse: a name no zone can carry leaves no row.

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

### State is a value — built in order, passed by reference

The daemon's state is one value, `bindizr_service::Context`, that
`bootstrap` builds in dependency order and hands to every front end as an
`Arc<Context>`: the configuration (`Config::load`, held behind a swap so
`reload` replaces it in place and `cx.config()` hands out the current
`Arc<Config>`), the database (`Db::connect(&config.database)`, a private
field only the service crate reads), the metrics (`Metrics::new`), and the
senders of the NOTIFY queue and the DNSSEC scheduler — whose channels are
created before the `Context` and whose workers are spawned after it with an
`Arc<Context>` of their own, since they need the database it holds. What
one front end owns lives in that front end's context, not in the daemon's:
`DnsContext` adds the transfer and ACL caches, `SocketContext` the control
channel. A handler takes its front end's context first, named for it
(`dns_cx`, `socket_cx`), and binds the daemon's from it where it needs one
(`let cx = dns_cx.daemon();`), so `cx` always names the daemon's `Context`;
the HTTP API, owning nothing of its own, takes that `Context` itself.
The daemon's own start is a fact the `Context` records once every front end
serves (`cx.started_at`, a `OnceLock` field set in the same breath as the
started-at gauge) and the `status` uptime reads. Every piece is a
constructor returning the value (`C-CTOR`), never an `initialize` that
fills a `static`, with a `stop` beside it where the daemon must drain it.
The daemon socket keeps its split — `bind` first, so a second daemon is
refused before anything else is built, then `serve`.

Two process globals remain, because the process is their receiver: the
`log` facade (`Logger::init` once, `set_level` on reload — the level and
format atomics are the logger's own state) and the stdout/stderr write
state behind `outln!`. A pure fact about the environment (colour
detection) may memoize in a function-local `OnceLock`. Nothing else is a
`static` — not the configuration, not a pool, not a metrics registry, not
a cache: a `static` hides a dependency the signature should show, and
forbids a second instance in one process, which is what a test wants.

### `--output` renders a result, so a command that is its output has none

Every CLI command that reports a *result* takes `-o/--output` and answers the
same shape in every format, so a script reads `-o json` wherever a person
reads the table. That means the daemon hands back a payload rather than a bare
message: the socket answer carries `MessageResponse` where it has nothing
richer to say, never `Value::Null`.

Commands whose stdout **is** the artifact take no `--output`: `zone export`,
`tsig-key export`, `dnssec keys export`, `completion` and `man` are redirected
into a file, and wrapping them would break that. `start` streams logs rather
than returning anything.

## Naming

### Data-access functions — `bindizr-db`

A data-access function is one SQL statement — the root function takes the
`Db` or the `Transaction` first, matches its backend, and calls the
same-named function in `mysql/`, `postgres/`, or `sqlite/` — and nothing
more: no error mapping, no rule. It lives in the module named for its
entity, and every name is an instance of

```text
<entity>::<verb>[_many][_by_<keys>][_with_<join>][_<predicate>][_tx]
```

No other segment exists. `_for_<x>` in particular is banned — the grammar has
no slot saying which role `x` plays: if `x` identifies rows it is `_by_<x>`;
if it is a value being written it is just an argument; if it is a condition
it folds into the verb (`upsert`) or the doc comment.

The first parameter is the connection: `&Db` for a statement on the pool,
`&mut Transaction<'_>` for `_tx`. The backend function beneath takes its own
`&Pool<Sqlite>` or `&mut sqlx::Transaction<'_, Sqlite>`, so every backend
carries the same set of functions and a missing one fails the root's
`match`; a root pair (`get_by_name` / `get_by_name_tx`) exists only where
the service needs both, and the `_tx` form alone where it needs the lock
(`LockLevel`).

**Verbs are a closed set — do not invent others:**

- `get` — one row by identity; returns `Option`. 404 mapping happens in the
  service layer, never here.
- `list` / `count` — a filtered collection / its cardinality. `list_all` is
  the unfiltered form.
- `create` / `update` / `delete` — literal row operations. A partial update
  names the one field it touches: `update_<entity>_<field>`
  (`update_zone_serial_tx`).
- `upsert` — insert-or-update; a conditional rule (the catalog serial
  advancing only when the digest changed) lives in the doc comment, not the
  name.
- `prune` — retention enforcement that may deliberately keep rows the cutoff
  matches (the newest zone version, serial boundaries) — semantics a literal
  `delete_*_older_than` would misdescribe.

`Transaction::begin` / `begin_read` / `commit` / `rollback`, the service's
`finish_tx` / `discard_tx` around them, and `ping` are transaction and
connectivity plumbing, not entity functions, and are the only exemptions.

**Segments:**

- `_many` / entity — the module names the entity, so a function omits it
  and marks the batch form `_many` (`record::create_many_tx`, never
  `record::create_records_tx`).
- `_by_<keys>` — equality on named columns, joined with `_and_` and never
  dropping `_id` (`list_by_zone_id_and_key_id_tx`). The entity's canonical id
  keys are elided, carried by the signature alone: bare `get`/`update`/
  `delete` take the row's own id, bare `list`/`count` the owning zone's id
  (`list_all` stays the unfiltered form). A non-id selector is always named,
  the canonical scope still elided around it (`get_by_serial(zone_id,
  serial)`, `list_by_name_tx(tx, zone_id, name)`), pluralized when it takes
  many values of that one key (`list_by_names_tx`). Every other key path is
  spelled in full: a non-canonical side (`list_by_token_id`,
  `count_by_key_id`, `delete_by_zone_id_tx`), and any key set whose elision
  would leave two functions of one module distinguishable only by their
  signatures — which is why the two-sided policy tables spell everything.
  `_by_filter` is the one non-column key: a struct of optional predicates for
  the listing queries.
- `_with_<join>` — the result carries joined data
  (`get_record_with_zone`); never a filter or semi-join.
- `_<predicate>` — a comparison filter as `<subject>_<comparison>`. Serial
  intervals keep their contracts in doc comments — the journal's
  `between_serials` is the IXFR half-open `(from, to]`, the versions'
  `in_serial_range` the closed `[from, to]`.
- Projections — a function returning one column rather than entity rows
  names that column, pluralized, where the rows would be, prefixed by the
  row set it filters when the module's entity does not say it
  (`dnssec_record::list_rrsig_zone_ids_expiring_within_refresh` — `rrsig`,
  since only RRSIG rows carry `expires_at`).
- `_tx` — runs on the caller's transaction, taken as the first parameter.

**Time filters** take a `cutoff` parameter and resolve the predicate's
subject one of three ways, most specific first:

- bound to the preceding `_by_` value when the timestamp is stamped on
  entering the selected state: `list_by_state_eligible_before`
  (`eligible_at`);
- the row's own timestamp column, verb-formed: `expiring_within_refresh`
  (`expires_at`, measured from `cutoff` plus the policy's re-sign window);
- elided for the row's own age: `older_than` (`created_at`) — the `prune`
  retention form.

Never spell a raw column name into the predicate (`state_changed_before`):
it reads as a bare column filter and hides that the state itself is an
equality selector the name must carry as `_by_state`.

### Service functions

- The functions of `bindizr_service::<entity>` carry the domain semantics
  and omit the entity the module already names (`zone::get_by_name`, not
  `zone::get_zone_by_name`).
  Verbs: `get_*` maps a miss to NotFound, `find_*` returns `Option`, `list_*`
  returns a collection, `count_*` a count; a domain verb is preferred where
  it says more (`advance_catalog_serial`, `sign_zone_tx`).
- A record mutation that also writes IXFR journal rows says so in the name:
  `*_with_changes_tx`. Preconditions (e.g. "caller already validated the
  rows") belong in the doc comment, not the name.
- A history row — kept so what happened can be read back later — is written
  by `save_*` (`save_version_tx`; `transfer::save_ok`,
  `save_refused`, and `save_failed`, named by the result `XfrResult`
  counts). `track_*` is a
  metrics counter, and `record` is never a verb: it is the noun of
  *Vocabulary*.
- Adjacent layers never reuse one name for different semantics (e.g. a raw
  row delete in `bindizr-db` vs. a delete-plus-journal-log in the service).

### Diagnostics — `status`, `check`, `doctor`

Three words for asking how things are, told apart by side effect and scope.
`status` reads and probes without acting (`zone status`, a `GET`). `check`
acts to find out — it asks a third party or sends a real message
(`dnssec check-ds` asks the parent, `secondary check` sends a NOTIFY) and is
a `POST`. `doctor` runs every check across the installation. A bare `check`
covers the whole object; `check-<part>` one aspect of it, so a narrow check
never takes the bare name.

### Free-function helpers

The `get_*`/`find_*`/`list_*`/`count_*` verbs above are reserved for data
access and mean the same thing in every crate, not just the service — a free
helper that computes a value never takes `get_`, and a metrics counter is
`track_`, never `count_`. The verb says what is read, not where: a stored
row is `get`/`list` in `bindizr-db`, the service, and a front end alike; a
value the `Context` holds — the configuration snapshot, the metrics, the
start time — is read by a noun (`cx.config()`, `cx.metrics()`,
`cx.started_at()`) and, where it changes, written by `set_<field>`
(`cx.set_config` on reload, `logger::set_level`). A row is never `set`: it
is created, updated, or deleted. `convert_` does not exist: a conversion is
`to_`, a parse `parse_`. Every other helper starts with one of these verbs:

- Conversion: the prefix says the cost (`C-CONV`) — `as_` a free borrow,
  `to_` work returning an owned value, `into_` consuming `self` — and a
  name says only what the call site cannot see. `to_<form>` when the
  source is evident there — a method's receiver, or the one argument
  (`to_fqdn(name)`, `to_sqlite_url(path)`, `to_response_data(status)`).
  `<source>_to_<form>` only when the source carries the meaning: several
  sources reach the same form (`labels_to_wire` beside `encode_name`), or
  the source is the point (`zone_name_to_member_id`). A conversion from
  one value with nothing else is a `From`/`TryFrom` impl, as *Rust idioms*
  says, before it is a helper. Two or more inputs make an
  assembly, `build_`. `parse_<thing>` — text or wire bytes into a typed
  value, fallible; an infallible reading is `to_` (`to_record_value_request`
  over the `--value` arguments). `encode_<thing>` / `decode_<thing>` — a
  typed value to and from its wire bytes (`encode_name`). `extract_<thing>`
  — one part out of an already-parsed message (`extract_ds_record_set`).
  `render_<thing>` — a typed value as multi-line human text
  (`render_diff_lines`); `display_<thing>` — one table cell;
  `<thing>_label` — a metric label value.
- Checks: `is_<x>` / `has_<x>` / `matches_<x>` — predicates returning `bool`.
  `classify_<thing>` — check returning core's typed `ParseNameError`, with no
  field context; `validate_<thing>` is the same check phrased against a named
  field and mapped to the caller's error type. The pair lives together.
  `verify_<thing>` — a cryptographic check that yields a result
  (`verify_tsig`). `check_<thing>` — a doctor-style diagnostic that reports
  instead of failing.
- Derivation: `build_<thing>` / `compute_<thing>` — assemble or derive a value
  from several inputs (`build_record_diff`, `compute_import_plan`);
  `group_<things>` partitions into a keyed map; `normalize_<thing>` —
  service-layer trim + canonicalize + validate, returning the canonical value
  or a `ServiceError`; `generate_<thing>` — fresh key, secret, or serial
  material.
- I/O: `send_` (one message out), `query_` (one DNS question), `probe_` (ask
  and report reachability or state), `fetch_` (pull a whole artifact, such as
  an AXFR), `resolve_` / `discover_` (names to addresses, the parent zone),
  `load_` / `read_` / `write_` (disk and streams), `print_` (stdout; CLI only).
- Flow: `handle_<thing>` — the entry point of one request or command;
  `apply_<thing>` — write a computed change set; `authenticate_` (who the
  caller is) / `authorize_` (what they may do).

A domain action or lifecycle step keeps its own verb (`sign_zone`,
`escape_label`, `enqueue_notify`, `run_udp_server`); the vocabulary above is
for the helpers around them, so an action never borrows a helper verb to
look like one (a `build_` that writes, a `to_` that sends). Predicate
methods read as a sentence about their receiver (`key.wants_parent_ds()`);
`is_`/`has_`/`matches_` are for free functions, which have no subject.

Noun names belong to pure derivations named by what they return, where a
verb would add nothing the return type does not say (`elapsed_ms`,
`record_set_digest`, `promotable_sep_key_ids`, `like_pattern`) — anything with
I/O or a side effect keeps its verb — and to constructors, which are named
by what they build: the kind alone where the module builds one kind of
thing (`unauthorized(message) -> Response` in the auth middleware,
`ServiceError::unauthorized`), with `_error` / `_response` added only where
one module builds several (`upstream_error_response`,
`signed_error`). Names an external trait fixes (`Log::enabled`,
`KeyStore::get_key`, sqlx's `compatible`) and serde default providers
(`default_<field>`) are outside the vocabulary.

One concept keeps one name across crates. Do not add a wrapper that only
reorders or renames the arguments of the function it calls — call it directly.

### Vocabulary — record, record set

User-facing text says **record** and nothing else: docs, OpenAPI annotations
and the payload docs in `bindizr_service::types`, CLI help and output, error
and log messages, e2e test names. A rule about one name and type is spelled
out ("records sharing a name and type share one TTL"); a zone snapshot is
"the zone's records at serial N". Never "RRset", "RR", "resource record", or
"record set" there.

Identifiers say **record** for one record and **record set** for the records
of one owner name and type, whatever layer they sit in: a wire item in core
is `TransferRecord`, `SignRecord`, or `UpdateRecord` (module and prefix
carry the wire/row distinction, not the word), a set-matching key is
`RecordKey` or `RecordSetKey`, a helper is `extract_ds_record_set`. The
stored row stays `model::record::Record`. **RR** and **RRset** (RFC 2181,
Section 5) survive only in protocol tokens, which keep their own spelling: the nsupdate RCODEs
(`NXRRSET`, `YXRRSET`, the `NxRrset`/`YxRrset` variants, lowercase log and
metric labels), `RRSIG` and its `Rrsig` types, the `domain` crate's own
`Rrset` and `sign_rrset`, ExternalDNS protocol words (endpoint, targets,
recordTTL), and RFC quotations. Check with:

```sh
grep -rnE "RRsets?\b|record set|resource record|\bRRs?\b" \
  docs README.md crates/bindizr/src/api crates/bindizr/src/cli \
  crates/bindizr-service/src/types
grep -rnE '"[^"]*(RRset|resource record|record set)[^"]*"' crates/*/src
grep -rnoE "\b[A-Za-z0-9_]*[Rr]r(set|s)?\b" crates --include='*.rs' \
  | grep -vE "Rrsig|rrsig|err$|stderr|Err$|formerr|Rrset$|NxRrset|YxRrset|sign_rrset|[yn]xrrset"
```

### Presentation — a value spells itself once

A fixed-set value has two spellings and no more. `as_str` is the storage and
API form, the one serde's `rename_all` also produces, and is what a row or a
metric label binds. `Display` is the presentation form, the one a person
reads in a table cell or a message, and every front end writes the value
with `{}` rather than spelling a variant itself. The two coincide unless the
presentation is a DNS mnemonic (`NSEC3`, `AXFR`), a human phrase
(`in sync`), or a notation (`RecordChange`'s `+`/`-`/`~`); a type whose
`Display` nobody reads has none. The CLI's free `display_<thing>` helpers in
`cli/output` render only what no type of ours can own — an `Option` (`-`), a
`bool` (`yes`/`no`), a timestamp, a duration, a truncated cell, and one cell
assembled from several fields — and every command reuses them rather than
formatting inline.

## Code style

### Comments

Give every named function a short purpose comment, even when its name already
suggests what it does. This includes private helpers, constructors, methods,
trait declarations and implementations, nested functions, test helpers, and
test functions. Use one sentence describing the operation or result, not a
walkthrough of the body. Keep an existing purpose comment instead of adding a
second one. Use `///` for Rust functions, a docstring for Python functions, and
`#` before shell functions; named Helm helpers use template comments. Anonymous
closures and generated dependency code do not need separate purpose comments.

Read the existing comments before adding a purpose sentence. Keep one coherent
documentation block per function, with the purpose first and any distinct
rationale in a following paragraph. Merge overlapping sentences. Put Rust
documentation before the function's attributes, and leave a blank line between
documented items. Put explanations shared by a module in its module documentation;
keep comments about individual steps beside those steps. Python docstrings come
first in the body; do not strand an existing function explanation above `def`.

Keep explanations of **why** as well: non-obvious behavior or invariants,
protocol/wire-format details, and public-API contracts. State each reason in
one or two lines, without spelling out consequences the reader can derive or
enumerating what the code shows. A purpose sentence and a necessary constraint
can share the same function documentation.

This includes short **in-function** comments giving the business or protocol
reason for a step — e.g. `// Increment zone serial so IXFR consumers can detect
this change`. Keep them even when the statement is obvious: they carry which
downstream system or invariant depends on the step. Do not strip them when
trimming.

Keep shell comments that mark workflow phases, such as validation, build,
installation, cleanup, and execution, including numbered steps. They help readers
follow execution order even when nearby commands or output describe the same
operation; the section-label restriction below does not apply to them.

Test functions also keep a short purpose comment stating what they verify;
overlap with the test name is fine. Within the body, comments explain why the
case exists — the regression or protocol rule it guards (cite the RFC section
for wire-format cases), format assumptions, and phase markers in long multi-step
e2e flows. Do not repeat each assertion in an inline comment.

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

### Imports never rename

A `use` never renames: `use domain::base::Record as WireRecord` hides which
name a body reads. A foreign name that collides with one of ours is reached
through its parent module (`inplace::Error`, `domain::base::Ttl`) or, when
the crate uses it in many places, through a `type` alias declared once
beside its kin (`WireName`, `WireRecord` in `dns::dnssec`); a module is
imported as itself (`use bindizr_service::{token, zone}`), never `self as
service`. The one rename is `as _`, for a trait imported only for its
methods (`use std::fmt::Write as _`).

### Workspace lints

`[workspace.lints]` in the root `Cargo.toml` is the one place lint levels are
set; every crate opts in with `[lints] workspace = true`. `unsafe_code` is
denied (the project is pure safe Rust), and `unreachable_pub` mechanically
enforces the visibility rule below. Keep the set small: a lint that fights an
idiom the codebase uses deliberately costs more than it catches, because the
build must stay warning-free without `#[allow]`. No `allow` hides a naming
the API guidelines reject: an acronym is one word (`MySql`, `Sqlite`;
`C-CASE`), so `clippy::upper_case_acronyms` stays at its default.

### No dead code, no `#[allow(dead_code)]`

The workspace builds warning-free with no `#[allow(dead_code)]` anywhere; keep
it that way. `bindizr-db` carries only functions with a live caller in the
service — do **not** add one "for symmetry" with an existing `_tx`/non-`_tx`
pair or to round out an entity's surface.

Its root functions are `pub` and consumed across crates, so rustc cannot see
when deleting a service call orphans one. After deleting a call, re-check the
layer below: a dead root function and its three backend functions go
together.

### Module file layout — `mod.rs`, never the sibling form

A module with submodules is a directory containing `mod.rs`
(`bindizr-core/src/dns/message/mod.rs`), not the 2018-edition sibling form
(`message.rs`
next to `wire/`). The community leans the other way, so the uniformity is
deliberate — do not "modernize" it.

Unit tests usually drive this: a `#[cfg(test)] mod tests` stays inline while
it is under **100 lines**, counting the module's own braces, and moves to
`<module>/tests.rs` once it reaches that — making the module a directory if it
was not one. The number is the rule, so a module that crosses it moves rather
than being argued over; `mod.rs` then declares it as `#[cfg(test)] mod tests;`
and the file opens with `use super::*;`.

### Visibility records usage

The scheme is three-level and nothing else: private, `pub(crate)`, `pub`.
`pub` means another crate touches it today, `pub(crate)` that only its own
crate does, private that only its own module does. **Do not use `pub(super)`
or `pub(in path)`** — their meaning depends on where the file sits, so it
reads wrong after a move and has to churn with every reorganization; half the
uses this codebase once had were at depth-1 modules, where `pub(super)` is
just an obscure spelling of `pub(crate)`.

Items and struct fields carry the narrowest of the three that compiles. A
struct mixing them is a measurement, not a design statement — widen a field
when the compiler asks, and no sooner. This keeps rustc's dead-code analysis
covering fields (`pub` fields are exempt) and keeps cross-crate struct
literals impossible.

Deliberate exceptions: `bindizr_service::types` payloads are fully `pub` (their
fields are the wire contract), and invariant-bearing types (`OwnerName`) keep
fields private behind constructors.

### Helper extraction — split at the second caller

Do not pre-split a function for a caller that has not arrived: extract the
shared helper when the second caller appears (`validate_record_set_shape` left
`parse_record_set_op` only when `adjust_record_set` needed it too). A single-caller
helper is justified by its contract, never by call count: the name plus a
narrow signature must let the caller be read without opening the body
(`normalize_ttl`). A name that merely labels a section of its one caller, or
a body correct only next to that caller's invariants, belongs inlined — long
sequenced bodies (`apply_changes`) stay whole rather than fragmented.
A Codacy complexity finding is never a reason to split a function: a bot
review cannot justify a helper, so leave the function whole unless the user
asks for the split.

### Methods and free functions — what a type owns

An inherent `impl` holds only these kinds of function; a function that is
none of them is a free function of the flow that needs it. The audit that
settled the list walked every method in the workspace.

1. **A constructor** (`C-CTOR`): an associated function returning `Self` or
   `Result<Self, _>` — `new`; `from_<source>` where `From` cannot spell the
   conversion; `parse` for text; a verb for how the value comes to be
   (`generate`, `import`, `compute`, `connect`, `load`, `spawn`); the kind
   alone where the type is an error or a refusal
   (`ServiceError::zone_not_found`, `TransferRefusal::refused`). A value a
   module builds from inputs, with the module's own error, is made this way
   (`DnssecKey::generate`, `ImportPlan::compute`, `ZoneChangeSet::compute`
   takes the ops as an input), never by a free `generate_` or `compute_`
   helper. I/O belongs here only when the value is the resource it opens
   (`Db::connect`) or a `Caller` authenticated from a request.
2. **A conversion or accessor**: `as_` a free borrow, `to_` an owned
   derivation, `into_` consuming `self`, and the `From`/`TryFrom`, sqlx,
   serde and `Display` impls beside them.
3. **A derivation or predicate about the receiver**: `is_`/`has_`/`matches_`
   or a verb phrase read as a sentence (`key.wants_parent_ds()`), computed
   from the fields and plain arguments; a peer of the same type may be an
   argument (`zone.soa_metadata_differs(&other)`,
   `key.signs_zone_data(&keys)`, `desired.matches(&record)`).
4. **A wire or protocol rule the type embodies**, failing with the type's
   own error (`UpdateRecord::validate_delete_shape`, `OwnerName::to_wire`,
   `RecordType::validate_value`) — even when one front end is the only
   caller, which maps the error to its own (`From<DeleteShapeError> for
   UpdateError`). A front end never re-wraps such a method
   (`ParsedQuery::signed_error_response` takes the optional signer itself).
5. **A builder step or a resource's operation**: `&mut self` steps take the
   values they add (`DnsMessageBuilder::add_record(&record, …)`); a type
   that owns a connection, a task, or a lock drives it
   (`Transaction::commit`, `UpstreamClient::send`, `NotifyWorker::stop`).
6. **The gate**: `Caller`'s `authorize_*` methods, which keep their
   `ServiceError` as *Who decides what* says.

Not a method, whatever its first parameter: a function that takes
`&Context`, `&Db`, a `Transaction` or the configuration to reach state that
is not the receiver's (a queue's `send_batch(cx, batch)`); an assembly of
several values of equal standing that returns a payload, a standard type or
a map (`build_record_diff(zone, …)`, `group_record_sets`,
`build_notify_message`); a service rule on a payload type — a payload's
constructors only reshape (`from_page`, `from_probe`, `From` impls), so
the page limit and the zone file's SOA are applied by `build_page` and
`build_create_zone_request` beside the flows that need them; a step of a
transaction; anything whose receiver would be a slice, an `Option`, or a
foreign type (the `domain` crate's aliases, `DateTime`). A method's error
is its module's own; `ServiceError` appears on a method only in the
service crate's own structs and the gate.

### Structs — a named shape that travels

A struct exists for a shape that travels with a name: a value that is
stored, passed on, compared, or keys a map another function reads
(`RecordSetKey`), and every payload. A pair the caller takes apart on
arrival stays a tuple (`let (token, secret) = token::create(…)`),
and values that travel together only inside one function stay locals. A
wrapper that only renames another struct's fields is not a struct — use the
original. One shape has one struct: two with the same fields merge, but two
with different fields are never generalized into one dynamic shape (a stage
list standing in for two timing structs).

### Struct literals stay at the use site

A struct literal is never the body a helper is extracted for. A function that
only assembles `SomeStruct { field: arg, … }` from its parameters hides which
fields are set without shortening anything — spell the literal at each site,
even when several sites fill the same fields and even though that duplicates
them. The exceptions are type-owned conversions deriving a value from one
source (`From` impls — `impl From<&Zone> for GetZoneResponse` — and the
`from_<source>` constructors *Rust idioms* keeps) and constructors guarding
an invariant behind private fields (`OwnerName`); a bag of loose parameters
is neither.

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
3. **e2e suite**: `e2e.rs` is the one harness binary — a `tests/*.rs` sibling
   would be built as a second one — and it declares a flat group per surface a
   request arrives on: `api/`, `cli/`, `nsupdate/` (RFC 2136), `xfr/` (a
   secondary's transfer and what authorizes it). What bindizr drives outward
   (NOTIFY, SOA and parent-DS probes, an inbound AXFR) stays with the surface
   that triggers it. A group splits into files only where a distinct command or
   route earns one — `zone import`, `POST /records/bulk` — and everything else,
   the CRUD and its listing and validation, stays in the group's `mod.rs`.
   Helpers sit at the narrowest scope that serves them: `tests/common/` when
   more than one group uses them, `<group>/common.rs` when one does, and
   private to the file otherwise. `common/dns/` holds the shared DNS logic
   every group pulls from (queries, transfers, the RFC 2136 builder, the fake
   parent), so its own unit tests live beside it in `common/dns/tests.rs`;
   apart from those, `common/` holds helpers only.
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
bindizr stop
```

Stop it with `bindizr stop` and check that no `bindizr start` process is
left before running the e2e suite: a leftover daemon holds the shared Unix
socket and every test fails with "Bindizr is already running".

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

## Release workflows — the tag and the inputs are the whole truth

`release.yml` publishes what the pushed `v*` tag says, `manual-release.yml`
what `Cargo.toml` and the dispatch inputs say, and `publish-image.yml` the
image tag typed in. Each validates its version before anything is built
(SemVer with every prerelease identifier checked, no build metadata, at most
128 characters, so a Docker tag can carry it), and that validation is the
only gate. `latest` follows the version in the release workflows, as
`packaging/scripts/build_image.sh` does; Publish Image has a checkbox for it.

Do not add guards against a release overwriting an earlier one, and remove
any that appear: comparing the tag with `Cargo.toml`'s version, refusing a
version whose tag names another commit, publishing `latest` only for the
newest version, serializing runs with `concurrency`, reserving the tag before
the image, or retrying a tag push. Docker tags are mutable pointers, so those
guards matter only when one version is released twice or tags are pushed out
of order; the process is one tag, one release, and the operator decides. Bot
reviews (Codex, CodeRabbit) raise these every round — they are declined, not
fixed.

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
