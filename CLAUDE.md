# CLAUDE.md

Bindizr is a Rust DNS control plane for authoritative name servers (BIND,
Knot DNS, NSD, PowerDNS). It manages zones/records via an HTTP API or CLI,
stores them in MySQL / PostgreSQL / SQLite, and propagates changes to the
secondaries via AXFR/IXFR using DNS Catalog Zones (RFC 9432).
It also serves nsupdate (RFC 2136).

## Working rules

Apply rules by responsibility: service entry point, transaction step, pure
calculation, type-owned operation, or test support. A narrowly scoped rule or
explicit exception takes precedence over a general summary. Examples illustrate
rules; existing names and implementations are not exemptions.

The [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) cover
what this file does not. Checklist tags such as `C-GOOD-ERR` identify their rules.
In an audit, distinguish a documented violation from a proposed convention or an
optional wording improvement; inspect behavior and call sites before deciding.

Contents:

- [Development workflow](#development-workflow)
- [Architecture and ownership](#architecture-and-ownership)
- [Service contracts](#service-contracts)
- [DNS contracts](#dns-contracts)
- [Rust design](#rust-design)
- [Naming](#naming)
- [Code organization and style](#code-organization-and-style)
- [Documentation and releases](#documentation-and-releases)

### Git

- Do **not** add Claude (or any AI assistant) as a `Co-Authored-By` trailer or
  otherwise attribute co-authorship in commit messages. Commits are authored by
  the repository owner only.
- Commit/push only when explicitly asked. Branch off `develop` before committing
  if currently on `main` or `develop`; pull requests target `develop`.

### Clean installs

Support clean installs only, not upgrades of existing deployments. Do not add
migrations, schema `ALTER`s, schema-version tracking, or compatibility shims for
old data/config/API formats; remove any that appear. Change definitions in place,
including breaking changes. Re-deploying the same version with different values
(`helm upgrade --reuse-values --set …`) is ordinary operation, not a version upgrade.

Startup `CREATE TABLE/INDEX IF NOT EXISTS` is idempotent setup for restarts, not
migration. MySQL's inline indexes and Postgres/SQLite's separate `CREATE INDEX`
statements follow backend syntax; reaching an old database is not a requirement.

## Development workflow

### Build, test, and lint

```sh
cargo build -p bindizr                                    # binary
cargo build --workspace                                   # workspace
cargo test --workspace --all-features -- --test-threads=1  # full suite (CI)
cargo clippy --workspace                                  # lint
cargo +nightly fmt                                        # format
```

- Tests run single-threaded: `.cargo/config.toml` sets `RUST_TEST_THREADS=1`.
  The explicit CI flag provides the same guarantee.
- Formatting requires nightly for `rustfmt.toml`'s `imports_granularity` and
  `group_imports`; stable ignores these unstable options.
- E2E tests use temporary SQLite databases and local processes by default.
  `BINDIZR_E2E_VERIFY_DNS=true` enables DB/BIND9 Docker containers; also set
  `BINDIZR_E2E_ARM=true` on ARM. Other crates' `--lib` tests need no external services.

### Benchmarks

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

## Architecture and ownership

### Workspace crates

| Crate | Owns |
| --- | --- |
| `bindizr-core` | Configuration, logging, DB models, DNS value types, wire encoding/decoding, DNSSEC signing, TSIG, zone-file parsing. Owns the production `domain` dependency; higher product layers use core types. E2E may use `domain` as a dev-dependency for independent protocol inspection. |
| `bindizr-db` | Row access through `Db` and `Transaction` enums over MySQL, PostgreSQL, and SQLite. Entity modules dispatch to same-named backend functions. SQL and error text are intentionally duplicated per backend; do not deduplicate them. |
| `bindizr-service` | Business logic, RFC 2136 apply, `Context`, and outbound `dns_client/` operations: NOTIFY, SOA/parent-DS probes, inbound AXFR. `transfer` persists what the DNS server served each client across restarts. Wire formats stay in core. |
| `bindizr` | Daemon bootstrap and front ends: HTTP API, CLI, Unix-socket IPC, inbound DNS listeners and dispatch (AXFR/IXFR/catalog/NOTIFY/nsupdate). |
| `bindizr-external-dns` | ExternalDNS webhook adapter forwarding to `/external-dns` over HTTP; no DNS logic or independent state. |
| `bindizr-e2e` | API/CLI/DNS end-to-end tests. Its binary targets let `env!("CARGO_BIN_EXE_…")` resolve inside the test package. |

### Modules and backend dispatch

Use modules as namespaces, not unit structs with associated functions
(`zone::create`, not `ZoneService::create`; `api::zone::routes`, not `ZoneApi`).
A struct represents a value or invariant (`C-METHOD`). Entity modules split by
verb re-export functions flat from `mod.rs`, so both callers and siblings use
`zone::create` / `super::lookup_by_name`, never `Self::` for module operations.
Service/db functions omit the entity their module names; front-end handlers keep
the full operation (`get_zone`, `list_records`). HTTP names are API-wide unique
OpenAPI operation IDs, and socket handlers use the same names.

Use an enum for a closed set. `Db` and `Transaction<'a>` match their backend
enums and pass the backend's own pool or sqlx transaction to its functions;
there is no runtime transaction-kind mismatch. A trait is justified by open
implementors or a generic bound (`impl IntoIterator<Item = &Record>`), not a
closed collection of implementations used only as boxed trait objects. Do not
introduce repository factories, boxed repository traits, or `async-trait` for
the three backends. Tests use a real `Context` over in-memory SQLite.

### State and process lifecycle

`bootstrap` builds one `bindizr_service::Context` in dependency order:
configuration, database, metrics, and NOTIFY/scheduler senders. Create channels
before `Context` and spawn workers afterward with `Arc<Context>`. Configuration
reload swaps the stored value; `cx.config()` returns the current `Arc<Config>`.
`Db` is private, accessible through `cx.db()` only inside the service crate.

Pass state explicitly. HTTP handlers use `State<Arc<Context>>`; spawned tasks
hold an `Arc<Context>`. Front-end-specific state stays in its own context:
`DnsContext` owns transfer/ACL caches, `SocketContext` the control channel. Name
these first parameters `dns_cx` / `socket_cx` and derive `let cx = dns_cx.daemon();`
when needed; `cx` always means the daemon context. HTTP needs no extra context.

Record `cx.started_at` in its `OnceLock` when every front end is serving, together
with the started-at gauge; status reads it for uptime. Components return values
from constructors, with `stop` where draining is needed, never `initialize` into
globals. Bind the daemon socket before building other state to reject a second
daemon early, then `serve` it.

Listeners own their accepted requests and connections. Shutdown stops new reads
and waits for accepted mutations, then stops and joins the scheduler before
flushing NOTIFY. A transfer may be interrupted for the secondary to retry;
canceling it must not leave a partially written frame usable by another reply.
The daemon's overall drain timeout bounds this wait.

Only two production process globals remain: the `log` facade (`Logger::init`,
`set_level`, its level/format atomics) and stdout/stderr write state behind
`outln!`. A pure environment fact such as color detection may memoize in a
function-local `OnceLock`. No other production `static` is allowed, including
configuration, pools, metrics registries, or caches. E2E globals for test sequence, run ID, and
the shared Compose stack are test coordination, not production dependencies.

Only a binary's `execute()` (the body of `main`) calls `std::process::exit`.
It lives in the binary crate's lib target so E2E can wrap and spawn it. All other
code, including core and db, propagates errors to its caller.

### Front ends and service flows

- **Authorization is the service's.** A management operation a front end can
  reach takes a `Caller` after its state parameters and gates itself; a
  transport never calls
  `authorize_action` on its own. The daemon socket passes `Caller::socket()`; an API with authentication
  disabled passes `Caller::unauthenticated_api()`. Both have global access,
  but their change origins remain distinct.
  Service-internal lookups that must skip visibility are `pub(crate)` under
  their own name (`zone::lookup_by_name`). The daemon socket
  authenticates its peer by uid (`peer_cred` on both ends: the daemon's own
  user or root); the socket directory's mode is a courtesy, not the boundary.
  NOTIFY takes no caller. A transfer or an nsupdate authenticates its TSIG
  key into a `Caller` (`Caller::authenticate_tsig_key`), or takes
  `Caller::unsigned_dns()` where the address ACL or
  `dns.nsupdate.tsig_required = false` admits an unsigned request, so the
  DNS plane passes the gates the API's writes do (`zone:transfer` through
  `authorize_zone_action`, the record actions through
  `authorize_record_access`).
  So do operations with nothing to gate: pure request normalization
  (`external_dns::adjust_records`), a token reading itself
  (`token::get_self`, keyed by the authenticated `ApiToken`), and
  the aggregate counts behind the unauthenticated metrics endpoint
  (`count_all`), which expose no zone data.
- **Transactions are the service's.** Service flows choose their lifetime
  through the database's transaction primitives; front ends do not open one.
  `Db` is a private field of `Context`, read by `cx.db()` inside the service crate
  alone, so the service's `*_tx` functions and its `Transaction` re-export
  are `pub(crate)`.
- **A use case has one home.** When two front ends answer the same question,
  the assembly lives in one place both reach (`zone::get_status`,
  shared by the HTTP API and the daemon socket), not once per transport.
- **A body is the service's to read.** The front end parses only what
  reaches it outside a body — a path or query parameter, a flag, the peer it
  authenticates into a `Caller` — and hands a body over whole, as its
  payload type: `role::grant::create(&cx, &caller, &role_name, &request)`, never
  the request's fields one by one, so both front ends pass the same value
  and neither parses for the other.

### Payload ownership and wire shapes

- `bindizr_service::types` owns shared HTTP API, daemon-socket, and CLI management
  payloads. `socket::types` owns daemon control messages, transport envelopes, and
  PID/listener reports. The HTTP adapter owns its external protocol shapes.
- Query extractors belong to their front end. Every handler's `Query<T>` appears
  as OpenAPI `params(T)` via `IntoParams`, including single switches; do not
  hand-write a second parameter list. Front ends reshape payloads for presentation
  (CLI table rows), never re-derive their contents.
- `DaemonCommand` is a data-carrying enum with
  `#[serde(tag = "command", content = "data")]`. Match directly into its typed
  variants; do not split a command into a kind plus `serde_json::Value` and re-parse.
- A field naming another entity is `<entity>_name` (`zone_name`, `notify_key_name`,
  `policy_name`). Serials use `u32`, key tags `u16`, counts `u64`. Change counts are
  `added` / `deleted` / `unchanged`; a diff uses `removed`.
- Responses use enums for fixed values, with schema values exposed. An optional
  response field is emitted as `null`, never skipped. A single entity is wrapped
  under its name (`{"zone": …}`); reports (status, check, diff, import, rollback,
  DNSSEC status) are bare. See [API type names](#api-type-names) for naming.

### CLI output

Every CLI command that reports a *result* takes `-o/--output` and answers the
same shape in every format, so a script reads `-o json` wherever a person
reads the table. That means the daemon hands back a payload rather than a bare
message: the socket answer carries `MessageResponse` where it has nothing
richer to say, never `Value::Null`.

Commands whose stdout **is** the artifact take no `--output`: `zone export`,
`tsig-key export`, `dnssec keys export`, `completion` and `man` are redirected
into a file, and wrapping them would break that. `start` streams logs rather
than returning anything.

## Service contracts

### Access control

- **Rights belong to a `Role`; a credential only proves who is calling.** An
  `ApiToken` and a `TsigKey` each name exactly one role (`role_id NOT NULL`)
  and carry no rights of their own, so one role serves several tokens and
  keys and revoking a right is one grant edit. There is no third credential
  type, and no credential is global: the socket (`Caller::socket()`), an
  API without authentication (`Caller::unauthenticated_api()`), and an
  unsigned DNS request the ACL or the configuration admits
  (`Caller::unsigned_dns()`) are the only global callers. A key that only signs outbound NOTIFY still names a role,
  an empty one when it needs nothing. Change attribution stays the
  credential (`ChangeActor::Token`/`TsigKey`), never the role.
- **A grant is a zone scope, a set of actions, and record constraints.**
  `RoleZoneScope` is `All` (row `zone_id` NULL, covering zones created later)
  or `Zone(ZoneId)`. `Action` is a closed enum spelled `<resource>:<action>`:
  `zone:read|create|update|delete|transfer`, `record:read|create|update|delete`,
  `dnssec:read|manage`, `secondary:read|manage`, `access:manage`,
  `audit:read`. The name
  pattern and type list (the `grant_pattern` grammar: `*`, `@`, `*.sub`, an
  exact relative name; `*` or comma-separated types) constrain `record:*`
  actions only. A role's rights are the union of its grants: an operation is
  allowed when one grant covers its action, zone, name and type. There are no
  deny rules. The `All` scope is spelled *all zones* wherever it appears —
  `RoleZoneScope::All`, the `all_zones` payload field, the `*_all_zones*`
  methods, and the prose of messages, docs and the UI — never "every zone"
  or "everywhere". `RoleGrants` answers every such question; the listing SQL
  repeats its name and type match for paging and is held to it by test.
- **Objects no zone owns need an `All` grant**: `zone:create` (a rename
  too, since a new name is one), `secondary:*`,
  DNSSEC policies under `dnssec:manage`, `audit:read`, and `access:manage`,
  which administers tokens, TSIG keys and roles — and so is equivalent to
  admin, since its holder can grant itself anything. The built-in `admin` role (every
  action, `All`) is ensured at startup and can be neither changed nor deleted;
  the first token is issued over the socket with `token create --role admin`.
- **Visibility**: a zone is visible when any grant of the role reaches it,
  whatever its actions (404 otherwise, so a scope cannot probe existence; a
  visible zone's denied operation is 403), and its details — SOA and
  settings, no records — read with visibility alone; `zone:read` adds
  status and the version list. Reading records needs `record:read`
  covering them; an update or delete finds its target by that or by its own
  write action, so a write-only grant reaches what it may change and no more.
  An update fills omitted fields from the stored record, so without
  `record:read` on it the update must give every field.
  Actions stay independent: a write or manage action never implies its read.
  A role holding one without the other works through the API, as automation
  wants; a client listing things to act on needs the read as well.
  A view the zone is rebuilt from — export, a stored version,
  a diff, a zone-file import — needs a grant with no name or type constraint,
  since half a zone re-applied deletes what it left out; a rollback reads
  the version it restores, so it needs the whole-zone read too.
- **A response shows only what the caller may read.** Existing rows reach a
  response — a write's diff, a delete's listing, a version — only as
  `authorization::ReadableRecords`, built by `Caller::readable_records`
  (dropping what no `record:read` grant covers) or a `WholeZoneRead` from
  `authorize_whole_zone_read`; `push_written` adds the caller's own writes.
  A new response carrying rows takes a `ReadableRecords`, not a filter at
  its site.
  Every record response carries the caller's `actions` on it, so a client
  offers what the service allows without re-implementing grant matching.
  The e2e `responses_hide_records_outside_read_grants` sweeps every
  route as restricted roles; a new route that returns records joins it.
- **A write-only grant learns what its write touches, never a value.** Write
  and read stay independent, with the boundary SQL, S3, Route 53 and Vault
  draw: a write that takes its material from the stored row needs
  `record:read` (a partial update, as `SET c = c + 1` needs `SELECT`); a
  conflict within the grant's scope may say what it hit — a record exists,
  the TTL its set holds, how many a delete matched — since a role that may
  overwrite a record holds more than knowing it is there; a value is never
  returned without `record:read`. What a write touches is what its request
  named: a stored record behind an id, or met by a whole-zone check, is
  named only to a caller who may read it; others hear the constraint broken.
  The leak sweep marks names and values across each role shape a write
  outruns its read in, which is this boundary as a test. Bot findings
  that a conflict or a count reveals existence or a TTL to a write-only role
  are declined.
- **What an operation needs is written in five places**, which change together:
  the operations table in `docs/cli/advanced.md`, the action table in
  `docs/cli/access-control.md`, the `Action` doc (the OpenAPI schema, so
  regenerate `docs/openapi.yaml`), `role grant --help`, and the UI's
  `ACTION_DESCRIPTIONS` (in the companion repository, see [Web UI](#web-ui)); the
  route's own OpenAPI description when it states one.
- **Each change is authorized by its kind**: a record create, update or
  delete needs the matching `record:` action at its name and type, per change
  in a bulk or ExternalDNS batch. An nsupdate prerequisite needs
  `record:read`, an add `record:create`, a delete `record:delete`, against the
  signing key's role; an add that replaces a CNAME, DNAME, or matching WKS record needs
  `record:delete` too, one that moves the record set's TTL `record:update`.
  An SOA addition needs `zone:update`, since it replaces zone metadata.
  A TSIG-signed transfer needs `zone:transfer` (the
  catalog zone an `All` grant); an unsigned one is the ACL's alone.

### Change attribution

Keep the request path, actor, and access scope separate. `ChangeSource` names
`Api`, `Socket`, `Nsupdate`, or `System`, never an authentication method or a
permission level. `changed_by` is an optional `ChangeActor` carrying a credential
kind and its name (`Token` or `TsigKey`), snapshotted without a foreign key.
Socket commands, unauthenticated API requests, unsigned updates, and background
work have no named token/key actor. The trusted entry point supplies attribution;
request payloads cannot choose it. `CallerScope` decides permissions independently
of the `ChangeAttribution` stored with a version. Persist an actor in the scalar
columns `changed_by_kind` and `changed_by_name`; both are populated or both null.
Decode them into `Option<ChangeActor>` at the row boundary. The API's object shape
does not dictate a JSON database column.

A management change — a token, role, grant, TSIG key, secondary or DNSSEC
policy created, updated or deleted, and a zone deleted, whose versions go
with it — is the one write no zone version records, so it saves an
`AuditLog` (`audit::save_tx`) in its own transaction, after its row write
and before commit: a change that rolled back leaves no row and a committed
one always has one. The entry names the entity kind and name (a grant's is
its role's), the operation, and the `ChangeSource` and `ChangeActor` a
version carries. Reads, refused requests, and startup setup (the built-in
`admin` role) leave none. `audit:read`, an all-zones action, lists the log;
`history.audit_max_days` bounds it, pruned by the scheduler pass beside
`history.zone_max_days`.

### Transactions and locking

One locking model covers the service layer; keep new code on it:

- A **zone-data mutation** (records, serial, journal rows, versions) is one transaction
  that locks the zone row (`zone::lookup_by_name_tx` in the service,
  `bindizr_db::zone::get_by_name_tx` / `get_tx` beneath it, `FOR UPDATE`) **before** any
  record rows — that order is the deadlock rule. Authorization, validation, and conflict
  checks decide on rows loaded inside that transaction, never on an earlier unlocked
  read, the credential included (next item). `lookup_by_name_tx` is the unchecked tx
  lookup; the flow re-authenticates and authorizes the locked row. Outside
  the transaction belong: pure input parsing/normalization, non-locking pre-reads done
  only to learn the lock target (commented at each site), friendly duplicate pre-checks
  that a UNIQUE/FK constraint backstops, authorization pre-checks the transaction
  repeats, and NOTIFY/logging after commit.
- **Every transaction that acts for a caller re-authenticates it**, reads included:
  right after its zone row (first, where it has none), `Caller::reauthenticate_tx`
  re-reads the token and its role's grants and every later check runs on them. A
  revocation — deleting a credential, revoking a grant — waits for the writes in
  flight (row locks on MySQL/PostgreSQL, the writer reservation on SQLite) and refuses
  every later one; a read authorizes and loads its content in one snapshot, so on
  SQLite, where a read holds no lock, it may finish after a revocation but serves only
  what it could read before. Every write that acts for a caller therefore runs in a
  transaction, management writes included; a TSIG transfer or update re-reads its key
  and grants the same way, and a transfer loads what it serves (AXFR records, IXFR
  delta, catalog members, SOA) in that transaction, a cached AXFR serving that version's
  content. A single statement that only records what already happened — the token's
  last-used stamp written during authentication, the transfer log — runs on the pool:
  nothing decides on it, and the caller's own transaction re-authenticates regardless.
  A read without a transaction, an outbound NOTIFY or probe, and an unsigned transfer
  (the address list as the request finds it) decide on the request's credential.
- **Reads**: one statement needs no transaction. A derived output that must
  be internally consistent (zone export, version detail, version diff)
  takes a transaction plus the zone lock. Paginated listings run count and
  page as plain statements; drift between the two is accepted.
- **Management writes** (tokens, TSIG keys, roles, grants, policies,
  secondaries) are one statement in a transaction that re-authenticates the
  caller: UNIQUE/FK constraints backstop their check-then-act races, read as
  friendly conflicts where the service calls the statement. A delete whose
  statement removed no row — its target went meanwhile — reports not found,
  as the zone delete's locked lookup does, and saves no audit row.
- MySQL and PostgreSQL use READ COMMITTED with row locks and constraints.
  SQLite uses WAL: mutations begin IMMEDIATE to reserve the database writer,
  and read-only transactions begin DEFERRED to read a consistent snapshot.
  `LockLevel` emits row-lock clauses only for MySQL/PostgreSQL. The common
  guarantee is atomic writes and a consistent protected read. ExternalDNS apply resolves authoritative zones from committed state inside
  its transaction; the residual race with concurrent zone creation is
  accepted.
- **Transaction locks and constraints provide concurrency guarantees.** The service
  layer never re-guards the gap between an unlocked pre-read and the locked
  read after it: no fingerprint or "changed meanwhile" comparison, no
  snapshot carried across a network wait, no in-process mutex or
  singleflight around a cache miss. Such a guard means something only if
  every path carries it, and none does. Work whose answer the transaction
  acts on — a parent-DS probe included — runs inside it under the zone row lock
  (or SQLite writer reservation); a read-only path runs it outside and accepts drift. The duplicate
  pre-check above is an integrity check the constraint backstops, not a
  concurrency guard.

### Mutation lifecycle

Service mutations follow one order: normalize supplied input, begin the transaction,
lock the target, re-authenticate and authorize, resolve omitted fields against the
locked state, validate the proposed state, apply, commit, then notify and report
success. Management operations re-authenticate before locking their own rows, as
[Transactions and locking](#transactions-and-locking) specifies. Reads keep their own transaction contract.

- Normalize supplied fields once at their owning boundary and carry the result
  forward. Independent validation, canonical comparison, and wire encoding may
  read that normalized representation; this does not require another cached
  request type. State-dependent defaults and cross-field checks use the locked
  rows. Preserve authorization and error precedence: an input parse may keep its
  `Result` until authorization permits
  reporting it. Never fill missing update fields from an unlocked pre-read.
- Build the actual candidate or change set. Do not repack an update as a creation
  request or add dummy fields to reuse validation. Share field validators and real
  domain data; keep optional values only while omission still has meaning.
- Validate before writing. Zone record mutations call `validate_record_changes_tx`
  on their proposed deletions and additions before the dry-run branch. Owner-local
  checks and whole-zone checks have different scopes; neither replaces the other.
  Version storage records an already validated change, without hidden validation
  or external side effects. Ordered DNS UPDATE applies protocol operations in its
  transaction, then validates their final state before signing and versioning;
  a rejected sequence rolls back in full.
- A dry run performs the same input, authorization and state validation as apply,
  then returns before writes or signing. It leaves no rows, serials, versions,
  successful-write metrics or NOTIFY behind. SQL constraints still backstop actual
  writes; a preview cannot promise that a later request or commit will succeed.
- Imports resolve text using the locked zone's TTL, or configured creation defaults
  for a missing zone. Parse once; AXFR passes records without rendering a master
  file. Plan and validate missing-zone imports before inserting the zone.
  A bulk import (`import_zones`) runs that flow once per zone, each in its own
  transaction in list order, so one zone's rejection or failure is reported
  beside the others' outcomes and stops nothing. Its zone list is the request's
  names or the members of the source's catalog zone (RFC 9432), read before
  any zone is touched; the `create` authorization, and the all-zones record
  actions a catalog needs, are checked once before the first transfer.
- NOTIFY, successful-write metrics and success logs follow commit. A no-op reports
  its outcome without claiming a version change. A preview log says `dry_run` or
  `applied`. A transaction result carries any change information these steps need.

These are responsibility boundaries, not a requirement for a helper or struct per
stage. Keep orchestration explicit; do not introduce a callback-based execution
framework. Input sources and protocols retain their distinct entry contracts.

## DNS contracts

Use existing wire and parsed types across DNS functions. Reading the same message
for a different protocol responsibility is allowed; `Message::from_octets` only
checks the header length. Add cached or intermediate representations only when
measured cost or a concrete invariant justifies their maintenance. TSIG request
verification returns authentication results; a separate encoder composes errors.
Service `notify` and `probe` flows select secondaries, load keys/history and
assemble reports; `dns_client` owns network exchanges and response validation.
Service flows choose configured targets and timeouts, including parent DS probes;
network clients receive those inputs explicitly. SOA/XFR response metrics and
transfer history reflect the final encoding/transmission outcome; handlers do
not count a refusal or success before work that could turn it into a failure.
Encoding failures remain typed outcomes until the handler
chooses its fallback response. UPDATE metrics describe request processing and
the committed mutation outcome: a failed response write cannot undo a commit.
Its TSIG error fallback is selected before that processing outcome is counted.

Listing services validate an explicit page limit before querying. An omitted
limit remains unbounded; HTTP supplies its default of 50, while the daemon
socket supplies none. An explicit limit is 1 through 1000. Collection paging and
response metadata only apply the validated window; they do not validate input or
choose another default. A documented use-case default, such as the secondary
transfer log's 1000, is resolved by that service entry point.

### Names and record values

An owner name is decoded into labels at the parse boundary —
`OwnerName::parse_in_zone` / `parse_absolute_in_zone` and
`dns::name::decode_name_labels` resolve the `\.`, `\\`, and `\DDD` escapes of
RFC 1035, Section 5.1. A dot inside a label is data, never a boundary.
`ZoneName::parse` uses the same octet-label and escape rules. DNS labels may
contain arbitrary octets (RFC 2181, Section 11), including non-LDH zone names.

Outside these name types and their parsers, do not answer a question about
name relationships with string operations. `ends_with`,
`split('.')`, or `strip_suffix` on a name is a bug even when it looks right:
it reads `evil\.example.com` as inside `example.com`. Use `OwnerName`'s
methods (`is_same_or_under`, `is_apex`, `to_fqdn`) or `is_label_suffix`.

Names are canonical by construction: ASCII letters are lowercased
(RFC 4343); other octets retain their values. Presentation renders nonprintable
and whitespace octets as `\DDD`, the in-label dot as `\046`, and
master-file metacharacters escaped, so one name has one spelling and a `.`
in rendered text is always a label boundary. That is what lets the
record-filter SQL compare owner names as text under a bytewise collation,
match a grant's subtree with `LIKE`, and concatenate them into FQDNs.

The row form is the type's, not a caller's: `from_row` decodes it, behind
the type's `sqlx::Decode`, and `sqlx::Encode` renders it, so bind an
`OwnerName` itself rather than a string you produced; no `From<String>`
exists to build one unparsed. `Display` is the presentation form, whose apex is `@` and not
the empty string a row holds. A `ZoneName` and a secondary's `AddressTarget`
(`host:port`, the port spelled out and the host lowercase) are rows the same
way: parsed once by the service, bound as themselves, and read back typed,
so nothing splits or re-parses their text at the point of use.

Choose the owner-name parser from the input contract, not its final character.
`OwnerName::parse_in_zone` accepts client input including `@`, a relative
name such as `www`, and an absolute name; it qualifies relative input with
the zone. `parse_absolute_in_zone` takes input already known to be absolute
(lookup form, wire owners), even when its rendered form omits the trailing
dot, and never qualifies it. With zone `example.com`, client input `www` is
relative, while a wire owner `www.other.org` must be rejected as out of zone.

A zone name crosses into the service as a `ZoneName`, parsed where its text
arrives by `zone::normalize_name`, which owns the request-phrased rejection
(`INVALID_ZONE_FIELD`; the root and a wildcard refused): an HTTP path or
query parameter in its handler, a socket command in its handler, a transfer
question in the DNS server once the catalog check has passed, where a name
the type refuses is answered NOTAUTH like a missing zone (an nsupdate too,
RFC 2136, Section 3.1.2), since no stored zone can match it. A name inside a request body
or a listing filter is parsed by the service function that takes that
payload, since the payload is its argument. Everything beneath —
the `_tx` lookups, the NOTIFY and probe clients, the zone-file parser, the
db layer, which binds a `ZoneName` as it binds an `OwnerName` — takes
`&ZoneName` and parses nothing again, and `dns.catalog_zone_name` is a
`ZoneName` from the moment the configuration loads. The transfer log's
`save_refused` and `save_failed` alone take the question's text, because a
refusal may come before any parse: a name no zone can carry leaves no row.

The effective catalog configuration must also leave wire space for generated
member owners; validate that bound after environment overrides.

Record values own their encoding: the SOA RNAME uses `SoaMailbox`, TXT uses
`TxtRecordValue`, and CAA uses `CaaRecordValue`. CAA property values are octets,
including empty and non-UTF-8 values; storage and export render them with
RFC 1035 escapes (RFC 8659, Section 4.1). TXT character-strings likewise carry
arbitrary octets and preserve segment boundaries. CAA tags and the names in
SRV, DNAME and NAPTR RDATA retain their original case; comparison and DNSSEC
canonicalization operate on separate wire data. Management creation of CAA
permits flags 0 or 128; UPDATE and import preserve unknown flag bits.
The root name `.` is a valid NS, CNAME, PTR, or DNAME target and SOA MNAME
(RFC 2181, Section 11);
it remains distinct from a literal dot label (`\.`).

The managed zone name still cannot be the root. NS, MX, PTR and SRV targets
cannot require CNAME or DNAME redirection within the zone (RFC 6672, Section 5.1).
A DNAME redirects only proper descendants; one stored below a non-apex NS
delegation is occluded and does not govern the parent zone's target validation
(RFC 5936, Section 3.5).

User records use a closed list of implemented types, including WKS. Unsupported
ordinary types are rejected across API, CLI, imports, and DNS UPDATE; there is
no opaque fallback or option to skip unsupported import records. Rejecting
unknown types is an explicit product exception to RFC 3597, Section 3's
transparent-handling requirement. A failed import leaves the zone unchanged. Numeric TYPE aliases
resolve only to implemented types. An UPDATE record of such a type is FORMERR
(RFC 2136, Section 3.4.1.2); a prerequisite may name any type and is evaluated
against the served zone. SOA and signer-managed DNSSEC data retain
their separate contracts.

Explicit UPDATE additions and deletions naming signer-managed DNSSEC types are
refused by policy (REFUSED), after wire-shape and RDATA validation (FORMERR).
Prerequisites may read these types; a name-wide delete changes user records and
lets the signer rebuild the derived view.

`WksRecordValue` owns IPv4/protocol/port parsing and bitmap encoding. WKS UPDATE
replacement compares its address and protocol (RFC 2136, Section 1.1.5). Ports
are numeric and protocols are numeric or TCP/UDP. Empty service lists encode no
bitmap bytes. As BIND's `fromwire_in_wks` does, reject trailing zero bitmap octets
before storing them, so the zone remains loadable by BIND. This is an
interoperability restriction, not an RFC 1035 requirement.

`NaptrRecordValue` validates flags after decoding presentation escapes:
empty or ASCII letters and digits (RFC 3403, Section 4.1). The application
defines flag meanings; DNS record validation does not restrict them to a list.

### RFC behavior and explicit exceptions

Except for the explicit deviations below, the DNS plane implements the RFCs it
cites (1034/1035, 1982, 1995, 1996,
2136, 2181, 3225, 4034/4035, 5155, 5936, 6672, 6891, 7766, 8767, 8945, 9103, 9432, 9619), and a
requirement one states is met as written: a MUST is implemented, a SHOULD
is followed unless the reason not to stands in a comment beside the code,
and a MAY is a design choice recorded here or in the docs. Interoperability
with a named server never loosens a MUST by default; where a server needs
one relaxed, that is an operator option documented with the section and the
server. The access-control model and the clean-install policy shape *how* a
requirement is met, not *whether*: XoT admits a request only when its TSIG
key and its registered address both pass (RFC 9103, Section 7.5), though
the plain listener takes either alone. Code that meets a requirement cites
the section (`RFC 9103, Section 7.1`), so a reader can check the text.

These SHOULD recommendations have explicit exceptions. TSIG verification does
not retain the latest Time Signed per key (RFC 8945, Section 5.2.3), because
UDP and concurrent stream requests can arrive out of order; every request
still passes MAC and Time Signed/Fudge checks. A truncated MAC, the
`hmac-sha1-96` Section 6 asks implementations to accept, is refused with
BADTRUNC under the local policy Section 7 permits: every key carries a
full-length MAC. Delegation NS and DS TTLs are recommended to match (RFC
4035, Section 2.4), but independently edited or imported sets retain the
operator's explicit per-type TTLs. Each RRset still has one TTL. Names are
lowercased when they enter, rather than preserved as RFC 1035, Section 2.3.3
and RFC 4343, Section 4 prefer, so that one name has one spelling in rows,
grants and exports; comparison stays case-insensitive either way.

Generated TSIG secrets match the HMAC output length (RFC 8945, Section 8).
Imported secrets retain a 16-byte minimum regardless of algorithm, preserving
the secret already shared with an external DNS server. The recommendation to
choose an output-sized secret applies to new keys; shorter imports are not
treated as malformed HMAC keys.

A NOTIFY transaction ends on any matching response, whatever its RCODE, or on
an ICMP port-unreachable error (RFC 1996, Sections 3.6 and 4.8); only silence
is retransmitted, `dns.notify.retries` times at `dns.notify.timeout_secs`
intervals, the operational parameters Section 3.6 leaves to the operator. A
retransmission repeats the same message on the same socket, so a late reply
to an earlier copy still ends it. An unsigned or unverifiable reply to a
signed NOTIFY is logged and ignored while the request waits (RFC 8945,
Section 5.4). An all-zones round notifies zones concurrently, so one silent
secondary cannot hold later zones behind its ACK/retry wait (Section 4.3).
The queue continues collecting writes during outstanding transactions;
intentional batching, measured from enqueue, is bounded by SOA REFRESH. The
16-zone preparation limit excludes ACK waits, and active transactions share
a connected UDP socket per target with no ID reuse on that socket. These
scheduling rules do not promise real-time delivery under OS or resolver failure.
Signed NOTIFY requests whose final size exceeds 512 octets include EDNS.
An import's AXFR client honors the server's keepalive timeout: zero closes
after the outstanding transfer, and a positive value bounds idle reuse
(RFC 7828, Section 3.2.2).

Serials wrap past 4294967295 to 1, never 0 (RFC 2136, Section 7.11), on
every automatic increment, the catalog serial included; a serial a request
states is taken as given. A zone's SOA REFRESH, RETRY, EXPIRE and MINIMUM
accept zero (RFC 1035, Section 3.3.13 sets no floor; MINIMUM 0 turns negative
caching off), though `dns.zone_defaults` may not default a new zone to it.
A CDS/CDNSKEY pair is published for a pre-published SEP key at once, before
the DNSKEY propagation interval RFC 7583, Section 3.3.1 waits out: the old DS
stays beside it (double-DS, RFC 6781, Section 4.1.2), so every validator keeps
a chain, and promotion still waits for both the interval and the parent's DS.

Generated DS/CDS use SHA-256, recommended by the IANA DS registry under
RFC 9904. Storing a user-supplied DS is not digest generation; do not apply
the signer's algorithm policy to raw DS input or parent-DS matching.
DNSSEC signs DS at an authoritative delegation, never data below an earlier cut.

Stored RDATA must fit a signed EDNS transfer message with worst-case question,
owner and key names, including OPT and TCP keepalive overhead. TLS requests
with an unsupported opcode receive REFUSED and, when EDNS was requested, EDE 21
(RFC 9103, Section 7.8); plain TCP/UDP return NOTIMP (RFC 8906, Section 8.1.4).
Classify these opcodes from the header without requiring a QUERY-shaped body.

Ordinary zone data is IN-only. An otherwise valid IN QUERY carrying an ordinary
RR of another class in Answer, Authority, or Additional receives FORMERR before
handler dispatch, including foreign-class IXFR SOAs (RFC 1995, Section 3).
OPT and TSIG retain their own CLASS semantics; UPDATE's ANY/NONE controls remain
in the UPDATE handler. Question-class refusals, EDNS version errors, and TSIG
validation retain their existing response codes and authentication behavior.

QUERY messages with QDCOUNT greater than one receive FORMERR before dispatch,
including requests with an unsupported EDNS version (RFC 9619, Section 4).
QDCOUNT 0 is not itself prohibited by that RFC; unsupported empty QUERY requests
default to FORMERR, while a readable unsupported EDNS version receives BADVERS.
Single-question requests also receive BADVERS for an unsupported EDNS version.
Preserve readable EDNS and authenticate TSIG before these refusals; TSIG
failures retain their specific errors. A message with an unreadable body receives
a header-only response; a header shorter than twelve octets receives no reply.
A transfer error about a zone this server holds (REFUSED, SERVFAIL) keeps AA set,
as RFC 5936, Section 2.2.1 recommends when in doubt; NOTAUTH, FORMERR and NOTIMP clear it.
The TSIG algorithm name is matched case-insensitively (RFC 1035, Section
2.3.3): the digest takes its canonical form (RFC 8945, Section 4.3.3), so
`HMAC-SHA256.` on the wire names the same key.

`dns.listen_addr` accepts a specific local IP or a wildcard (`0.0.0.0`, `::`).
UDP replies use the query's local destination IP and the listener's bound port
(RFC 2181, Sections 4.1–4.2), including wildcard listeners on Linux and macOS.
Enable packet information before starting the listener; reject truncated
datagrams or missing destination metadata instead of guessing the reply source.

Omitted API/DNS addresses default to `0.0.0.0`; their ports default to `3000`
and `5300`. The database type defaults to SQLite and the logging level to `info`.
These defaults also apply when their sections are absent. The selected database
still needs its location. Parse the file and fill defaults, then apply environment
overrides before validation; explicit invalid values remain errors.

DNS response budgets use `ResponseLimit`. Ingress reads EDNS from `ParsedQuery`
or `QueryMetadata` and chooses UDP/EDNS or stream; UPDATE and outbound UDP
clients use `QueryMetadata` when they need only response metadata, not QUERY
validation. Authentication and service operations return outcomes without
encoding packets or taking response budgets. Response encoders use the request's
budget, from their existing parsed input or an explicit `ResponseLimit` when
they receive raw bytes. A builder holding `ParsedQuery` accepts no second size
override. Final encoders check compressed bytes after OPT and TSIG; UDP send
checks the same budget before I/O. Transfer builders may estimate size while
splitting stream messages, but that estimate never replaces the final check.
UDP may rebuild a TC response or compact TSIG validation error; stream overflow
is an error. Commit a TSIG chain only when its completed message fits. Outbound
UDP clients discard responses larger than their advertisement within the
original deadline. Fixed name, RDATA, and TCP frame widths remain checked by
their owning types; signing and field composition primitives do not take
transport budgets.

EDNS parsing and response encoding are shared by QUERY, UPDATE, and TSIG errors.
A readable OPT retains its version and DO bit even when rejected with BADVERS;
response OPTs copy DO and clear reserved flags (RFC 3225, Section 3).
BADTIME responses sign the complete response, including OPT, and the six-byte
server time in Other Data (RFC 8945, Sections 4.3 and 5.2.3). If a TSIG
validation error exceeds the UDP limit, omit its question and re-sign the
same error, retaining its time fields, OPT and full MAC. Stream errors keep
their question (RFC 5936, Section 2.2.2).
Every TSIG MAC includes the original Other Len and Other Data octets. Requests
require Error zero; requests and responses both require the final Additional
TSIG to carry CLASS ANY and TTL zero (RFC 8945, Sections 4.2 and 5.2).
Bindizr requires full-length TSIG MACs. Key, MAC, and time validation precede
this policy; authenticated truncations receive signed BADTRUNC, while invalid MACs
receive unsigned BADSIG (RFC 8945, Sections 5.2 and 5.3.2).
TSIG outside Additional, or other malformed TSIG placement, receives unsigned
FORMERR before UPDATE authority or permission checks (RFC 8945, Section 5.2).

An UPDATE reaches the service with its zone class and complete wire sections.
The parser checks the zone count and SOA type; the service decides authority
over the name and class. A class other than IN is NOTAUTH, even when its name
matches a stored zone (RFC 2136, Section 3.1.1). After locating the authoritative
zone, the service keeps RFC 2136, Section 3's order: an unsigned request
`dns.nsupdate.tsig_required` refuses is refused there, after NOTAUTH and before
anything is read; then the prerequisites are decoded and evaluated one by one
in wire order (Section 3.2.5, once the read grant each needs is checked), the
value-dependent sets compared whole after the section (Section 3.2.3); then
every update record's owner, wire shape and type are checked before the grants
on it and before any operation is selected (Sections 3.3 and 3.4.1). Even a
delete that will be ignored must pass that prescan. An unsupported EDNS version
is BADVERS ahead of every policy refusal (RFC 6891, Section 6.1.3). The response
echoes the zone section alone, as BIND, Knot and PowerDNS do: an explicit
exception to RFC 2136, Section 3.8. Checked owners remain
`OwnerName` values through authorization and execution, without re-parsing.
Prerequisites compare with the complete served zone at that transaction's
serial: the SOA, ordinary records, and signer-generated DNSSEC records.
Their wire type and canonical RDATA identify an RRset independently of
storage; the writable `RecordType` enum never decides whether it exists.
SOA additions are resolved in wire order using RFC 1982 comparisons. Equal,
older, undefined-distance and non-apex SOAs are ignored; an advancing SOA
passes the existing zone-write policy and supplies the request's final serial
(RFC 2136, Sections 3.4.2.2 and 3.6). SOA metadata, record changes, signatures
and the version commit together at that serial. Serials span 0..=4294967295,
are stored in signed 64-bit columns and advance modulo 2^32. History older
than the unambiguous RFC 1982 half-range is retired in that transaction, so
serial reuse cannot mix journal generations. The transfer cache keys snapshots
by their immutable version id, since a wire serial can repeat. Zone-policy failures are REFUSED,
not malformed RDATA.

An equal- or newer-serial IXFR receives only the current SOA from the
authorized snapshot, independent of journal retention, including for catalogs
(RFC 1995, Section 2). UDP IXFRs return the current SOA. RFC 1982 determines
serial order; undefined comparisons and unavailable deltas use AXFR.

## Rust design

### Standard, asynchronous, and Unix APIs

Use stable std/Tokio APIs on the supported platforms. Choose by the operation's
contract, not by the system call the library uses internally. Unix-specific
`std::os::unix` extensions are part of std.

| Responsibility | API |
| --- | --- |
| Values, paths, addresses, synchronous file operations, metadata, permissions, PID, process creation/replacement/exit | `std`, including `PermissionsExt` and `CommandExt::exec` |
| Asynchronous files and sockets, readiness, tasks, timers, signals, Unix peer credentials | Tokio, including `UnixStream::peer_cred` |
| DNS UDP packet information and per-datagram reply source selection | `nix` in `dns::udp` only, using `setsockopt`, `recvmsg`, and `sendmsg` |

HTTP servers use `axum` (`axum-server` for HTTPS); the ExternalDNS adapter's
HTTP client uses `reqwest`. HTTPS, DNS TLS, and database TLS share ring-backed
`rustls`; `tokio-rustls` connects it to Tokio streams. OpenSSL is needed by
`domain` for DNSSEC RSA key generation and Ed448.

Enable dependency features where they are used: core needs SQLx row derives;
DB owns its drivers, runtime, and TLS. Keep Tokio's features explicit.

The effective-UID getter in `socket::read_own_uid` uses a Tokio Unix socket pair
and its peer credentials; keep both endpoints alive until the read completes.
The DNS UDP listener keeps its Tokio socket and uses `UdpSocket::async_io` for
readiness around nix calls. Enable only nix's `net` and `uio` features; libc types
come through nix, with no direct libc calls. Other sockets and Unix operations
stay with std/Tokio. Do not introduce a general syscall layer. Application
`unsafe` remains forbidden.

### Structs and literals

A struct exists for a shape that travels with a name: a value that is
stored, passed on, compared, or keys a map another function reads
(`RecordSetKey`), and every payload. A pair the caller takes apart on
arrival stays a tuple (`let (token, secret) = token::create(…)`),
and values that travel together only inside one function stay locals. A
wrapper that only renames another struct's fields without changing its
meaning or invariants uses the original. Merge structs only when their
fields, domain meaning, invariants, and contract are the same. Nominal types
such as `ZoneId` and `RecordId` remain distinct despite identical storage;
interchanging them is exactly what their types forbid. Shapes with different
fields are not generalized into one dynamic shape (a stage list standing
in for two timing structs). A shape that crosses a process
boundary is spelled on each side: the adapter's `BindizrRecord` mirrors the
service's `ExternalDnsRecord` over HTTP, since the adapter depends on core
alone and a payload does not belong there.

In production, a struct literal alone does not justify a helper. A function that
only fills `SomeStruct { field: arg, … }` from its parameters hides the fields
without simplifying the call; keep the literal at each site even when repeated.
Type-owned representation conversions ([Conversions](#conversions)) and
constructors guarding private invariants are allowed; a bag of loose parameters
is neither. Test fixtures follow [Test helpers](#test-helpers).

### Function boundaries

Keep entry points separate when callers require different target scopes,
authorization, failure or return guarantees, or resource lifetimes. A short
entry point can establish that contract: selecting enabled secondaries and
diagnosing one specified secondary remain separate operations even when
their sending code is shared. Combine entry points only when their contracts
are the same and their differences are ordinary inputs to that operation.

Share common implementation beneath these entry points. Do not introduce a
selector, an empty `Option`, a one-element collection, or dummy arguments
just to combine different operations. The enum/bool rules describe how to
express a real input; they do not justify inventing one to merge functions.
Callbacks need actual alternative implementations or a deferred execution
contract. When every caller passes the same callback, pass the data and call
the implementation directly.

Judge a change by duplicated logic and maintenance points removed, not by
function count or body length. Identify the contracts to preserve, the
implementation to share, and any new arguments or branches before merging.

### Helper extraction and transport boundaries

Do not pre-split a function for a caller that has not arrived: extract the
shared helper when the second caller appears (`validate_record_set_shape` left
`parse_record_set` only when `adjust_record_set` needed it too). A single-caller
helper is justified by its contract, never by call count: the name plus a
narrow signature must let the caller be read without opening the body
(`normalize_ttl`). A name that merely labels a section of its one caller, or
a body correct only next to that caller's invariants, belongs inlined — long
sequenced bodies (`apply_changes`) stay whole rather than fragmented.
A Codacy complexity finding is never a reason to split a function: a bot
review cannot justify a helper, so leave the function whole unless the user
asks for the split.

Keep UDP, TCP, and TLS send/receive entry points separate, including test
helpers (`send_update_udp`, `send_update_tcp`). Share message construction
and signature handling. Each transport owns connection establishment,
negotiation, and transport-specific limits. Established streams may share
framing and query handling when their timeout and lifetime guarantees match.
Similar call sequences alone do not justify merging transport entry points
behind a selector.

### Methods and constructors

An inherent `impl` contains only operations the type owns. Returning a type does
not by itself make an operation belong to it (`C-METHOD`, `C-CTOR`).

| Responsibility | Form and boundary |
| --- | --- |
| Construct `Self` or `Result<Self, _>` | `new`, `parse`, `generate`, `import`, `compute`, `connect`, `load`, `spawn`; error/refusal constructors name the condition (`zone_not_found`, `refused`). A module-owned value uses its constructor and module error (`ImportPlan::compute`, `DnssecKey::generate`); free `generate_` produces standard/foreign material (`generate_serial`). |
| Convert or access representation | `From` / `TryFrom`, `from_<source>`, `as_` / `to_` / `into_`, sqlx, serde, `Display`; see [Conversions](#conversions). |
| Derive from or test the receiver | `is_` / `has_` / `matches_` or a meaningful phrase (`key.wants_parent_ds()`); plain inputs and peers are allowed (`zone.soa_metadata_differs(&other)`). |
| Enforce the type's wire/protocol rule | `UpdateRecord::validate_update_shape`, `OwnerName::to_wire`, `RecordType::validate_value`, using the module's error. A front end maps that error and does not wrap the method just to rename it; `ParsedQuery::build_signed_error_response` takes its optional signer itself. |
| Operate a builder or owned resource | `&mut self` builder steps, `Transaction::commit`, `UpstreamClient::send`, `NotifyWorker::stop`. |
| Authorize the caller | `Caller::authorize_*`, retaining `ServiceError`. |

An infallible no-argument `new() -> Self` has a matching `Default`; a fallible
`new() -> Result<Self, _>` needs none. Use builders for incremental construction,
not optional-field structs that `Default` and update syntax already express
(`ZoneFilter { name, ..Default::default() }`; `C-BUILDER`).

Constructor I/O may open an owned resource (`Db::connect`), load the value's own
stored representation (`Config::load`), start work controlled by the returned
handle, or authenticate a `Caller`. Unrelated application reads remain a service flow.

Use a free function for transaction steps; access to unrelated `Context`, `Db`,
configuration, or transaction state; assembly of equal-standing inputs into a
payload/standard type/map; and operations whose receiver would be a slice,
`Option`, or foreign type. A payload's methods only reshape representations, not
apply service policy. Page limits/metadata live in `pagination`, probe classification
in `probe::build_secondary_status`, and imported SOA preparation in
`prepare_zone` beside the import flow. Methods use their module's error;
`ServiceError` appears on methods only in service-owned structs and the caller gate.

### Conversions

Use `From` / `TryFrom` for a value derived from one other value and nothing else
(`impl From<&Zone> for ZoneResponse`; `C-CONV-TRAITS`). Never implement `Into` or
`TryInto` directly, or a conversion trait for a `Result`; the caller applies `?` first.

Use `from_<source>` when the source type alone does not express the representation
(`OwnerName::from_row`, `SoaMailbox::from_email`, `Run::from_dry_run`), or the main
source needs supplementary representation data (`from_secondary(secondary,
notify_key_name)`). These conversions do no I/O and make no service policy decision.
Combining independent inputs or classifying an outcome is assembly; ownership,
not argument count, decides whether it is a constructor or free function.

Prefixes express cost (`C-CONV`): `as_` returns a borrowed view or allocation-free
`Copy` scalar, `to_` does work and returns an owned value, `into_` consumes `self`.

### Typed inputs

- A boolean states a fact (`enabled`, stored `incremental`, `aa`, `rd`, cache hit).
  A choice of policy, interpretation, or execution uses an enum (`Run`, `DsCheck`,
  `Holddown`, `NotifySerial`, `SigningPass`, `DnssecKeyLayout`, `LabelCharset`,
  `TransferMessagePosition`; `C-CUSTOM-TYPE`). Three or more such choices on one
  call become named fields of one struct; two remain parameters. Use an explicit
  `All` variant for all-target semantics, not `None` in `Option<&str>`.
- The boundary reading a flag/query builds its enum (`Run::from_dry_run`), and
  the socket carries it typed. The service reads body flags. A request field
  spelling an enum remains a `String`, parsed by the service through `FromStr`
  with `INVALID_INPUT` listing supported values. Responses use the enum. A policy
  name stays a string because it names a row.
- Domain numbers are newtypes (`Serial`, `Ttl`, `SoaInterval`, `KeyTag`, `Days`)
  with `From` / `TryFrom` row/payload conversions and sqlx encoding (`C-NEWTYPE`).
  Entity IDs live beside their rows, one `id_newtype!` per kind. Raw request
  numbers are validated into these types by the service; `#[schema(value_type = …)]`
  preserves wire schemas. Record priority remains `Option<i32>` until `RecordType`
  validates it with the value and type-specific wording (`MX priority`).
- Use lossless `From` casts where available (`i64::from(count)`, `usize::from(len)`).
  Keep `as` for platform-width casts without a standard conversion (`usize` to
  `u64`, `u32` to `usize`) and enum discriminants; other casts truncate or change
  sign intentionally.

### Common traits

Derive traits according to the value's contract (`C-COMMON-TRAITS`, `C-DEBUG`):

| Trait | When |
| --- | --- |
| `Debug` | Every type. |
| `Clone`, `PartialEq`, `Eq` | Fields permit them and the type owns no resource. A resource has external identity: socket, pool, task, lock, child process; cloneable protocol state such as a TSIG sequence is not one. A shared resource handle (`Shutdown`, `SocketContext`) clones but does not compare. |
| `Copy` | Fieldless enums and structs whose fields are all `Copy`, regardless of size. Generic wrappers derive traits conditionally, including `Copy`. |
| `Hash`, `Ord` | Map keys or sorting. |
| `Default` | An empty/default value is meaningful, including filters and infallible no-argument constructors. |
| `Serialize`, `Deserialize` | Every process-boundary payload, including adapter-local HTTP shapes and responses read by the CLI. Query extractors and final CLI presentation structs need only their transport's direction. DB rows carry neither. |

Enums with stored, wire, or textual forms follow [Presentation](#presentation).
Control enums without those forms need neither text conversion nor `Display`.

### Errors

Production fallible functions return `Result` with a module-owned `thiserror`
type implementing `std::error::Error + Send + Sync`, preserving `source()`
(`C-GOOD-ERR`). Foreign trait implementations use the error fixed by that trait.
A helper doing only standard I/O with no failure classification of its own may
return `io::Result`; choosing a kind or writing a message requires its own error
variant, not `io::Error::new`.

- Preserve typed causes between operations. No `Result<T, String>`, `type Err = String`,
  failure-carrying `Option<String>`, or `From<String>` / `From<&str>` on
  error types. Variant fields carry site-specific details. Response/diagnostic
  text is presentation at the boundary.
- Cross layers with `From` and `?`. Use `map_err` only to add classification or
  context absent from the cause (UNIQUE to `zone_conflict`, `internal_with_source`);
  never flatten a source into a formatted message.
- `ServiceError` variants match `ErrorCode`s and carry the wire message.
  `Internal`, `DnssecSigningFailed`, and `DnssecDsUnverified` retain their cause as
  a source. Operational failures mapped to `InvalidInput`, such as an inbound
  AXFR failure, retain theirs too; plain input or policy classifications need
  no artificial cause. `code()` and `Display` supply the payload; front ends map
  codes to HTTP status, CLI exit
  code, or DNS RCODE. The service knows no HTTP. Other layers use their own errors
  (`DaemonError`, `DnsError`, `CliError`) with `From` conversions.
- Box `domain` errors in `dns::LibraryError`; their types vary and callers do
  not match them. Only foreign failures without `Error` (`SigningError`, `TxtError`)
  keep text in a `reason` field instead of a source.
- Share error types within a layer when handling is the same. Preserve distinct
  contracts/recovery decisions (`StartDnsError`, `SendIxfrError::NotStarted` /
  `Partial`). No wrapper variants solely to name handlers. Logs supply operation,
  transport, and peer. Shared errors do not merge protocol entry points.
- Do not replace `Result` with `unwrap` / `expect` in production, even for errors
  a static definition makes impossible (`Metrics::new` returns
  `RegisterMetricsError`). Read `Infallible` with `let Ok(()) = …` and restructure
  representable invariants (use an enum for a pre-read lock target). Remaining
  `expect`s guard a constructor invariant, poisoned lock, or a foreign builder
  limit a single question cannot reach. See [Test helpers](#test-helpers) for tests.

Error names follow [Type naming principles](#type-naming-principles). Authored
error prose starts lowercase without a trailing period; protocol tokens, proper
names, and wrapped errors keep their original spelling.

## Naming

### Type naming principles

Name a type for its domain and responsibility, not whether it is a struct or enum.
Inspect fields, variants, and call sites. A precise noun (`Run`, `DsCheck`,
`Holddown`, `SigningPass`) needs no generic suffix.

- A name must hold for every value/return path, including previews and skipped
  writes. `Prepared`, `Resolved`, `Validated`, and `Applied` guarantee those phases;
  an output that may not be applied is an operation `Result`, not `Applied*`.
- A prefix describes the type's own responsibility: database-loaded input does
  not make an in-memory request key holder a `DbKeyStore`.
- Acronyms are words (`MySql`, `Postgres`, `Sqlite`, `Tsig`, `Dnssec`; Rust RFC 430,
  `C-CASE`). Protocol tokens keep their spelling in strings (`"AXFR"`), not identifiers.
- Errors use `<Verb><Object>Error` (`ParseNameError`, `VerifyResponseError` for
  `verify_response`) or `<Layer>Error` (`DatabaseError`, `ServiceError`;
  `C-WORD-ORDER`). Cover every carried failure: an encoding/size error is not `Overflow`.
- A DNS `Response` is the whole reply; an `Answer` is its answer section or an
  answer record. An owner/type lookup key names records (`RecordKey`), not DNSKEY
  or TSIG cryptographic keys. Module-local `Args`, `Command`, and `State` may stay
  short when unambiguous. External protocol/dependency types keep their vocabulary.
- Keep distinct contracts distinct even when names coincide; qualify through the
  parent module. Naming rules do not require new wrappers, new phase structs, or
  a split into `Response`, `Plan`, and `Result` for every flow.
- Align related parameters, fields, functions, SQL constants, examples, and schemas
  when renaming a concept. Regenerate OpenAPI from source. A rename does not itself
  authorize changes to serialized fields/values, predicates, permissions, or behavior.

### API type names

| Responsibility | Name | Example |
| --- | --- | --- |
| Response data, including nested objects | `<Subject>Response` | `ZoneResponse`, `PaginationResponse`, `RecordDiffResponse`; no `Info` suffix for reuse or nesting. |
| One entity wrapped under its named field | `Single<Subject>Response` | `SingleZoneResponse { zone: ZoneResponse }`; distinguishes the existing envelope from its reusable payload, independent of read/write operation. |
| Operation-specific input/output | `<Operation><Subject><Request\|Response\|Query>` | `CreateTokenResponse`, `WriteZoneResponse`, `CheckSecondaryResponse`, `AdvanceDnssecRolloverQuery`. |
| A whole operation's input | `<Operation><Subject>Request` | `DeleteRecordsRequest` includes selection and mutation controls such as `dry_run`; it is more than a filter. |
| HTTP query extraction | `<Subject>Query` or the operation-specific form above | Front-end extraction, not a shared payload role. |
| Grouped operation inputs | `*Params`, `*Options` | Use only where a more specific responsibility does not name the group. |

Use a base-form verb followed by the complete subject and suffix: `CreateTokenResponse`,
not `CreatedTokenResponse`; `WriteZoneResponse`, not `ZoneWriteResponse`.
Request/response pairs share their stem (`CreateBulkRecordsRequest` /
`CreateBulkRecordsResponse`). Protocol qualifiers are part of the subject
(`AdjustExternalDnsRecordsRequest`). The same order applies to query types
(`ListZoneVersionsQuery`, `DiffZoneVersionsQuery`), entity handlers, and internal
command variants (`create_bulk_records`, `CreateBulkRecords`). Preserve existing
wire command names with explicit serde renames when internal names change.

These payload rules also cover socket/CLI JSON and adapter request serializers
and response deserializers. A response payload uses `Response`, not `Body`;
transport extractors such as `JsonBody` keep their distinct role.

Share a response when operations have the same contract (`WriteZoneResponse` for
create/update); do not clone it into operation-specific types. Reusable data and
state reports need no invented verb (`ZoneResponse`, `DnssecStatusResponse`,
`RecordDiffSummaryResponse`). `Status`, `Diff`, and `Summary` describe data;
`DiffZoneVersionsResponse` names a comparison operation.

Domain models/values (`Zone`, `Ttl`, `RecordValue`) and bidirectional protocol
records (`ExternalDnsRecord`) retain their domain names even inside responses.
A request stays a request when transported in HTTP query parameters or a socket
payload; transport location alone does not make it a `Query` or `Filter`.

### Domain and operation type names

| Responsibility | Name | Boundary |
| --- | --- | --- |
| Matching rows | `<Subject>Filter` | Singular entity, no query verb: `ZoneFilter`, not `GetZonesFilter`. An enum selects a predicate; a struct combines them. |
| Work selected for execution | `<Operation>Plan` | Selected actions and data before execution. An `IxfrPlan` may select SOA-only, incremental, or full transfer; a `Delta` is the changes themselves. |
| Executed/previewed operation output | `<Operation>Result` | Includes no change or skipped writes; may be internal rather than a wire response. |
| Reusable lookup state | `<Subject>Cache` | Owns entries and their reuse/expiry (`AddressCache`); a resolved value or entry is not the cache. |
| Several timing values | `<Subject>Timings` | `SigningTimings`, `ImportTimings`; a single timing value is singular. Entity names stay singular regardless of field count. |
| Resources a caller may access | `<Subject>Scope`, `scope_<key>` | Authorization scope (`scope_role_id`), not search criteria. |
| Entity representation to read | `<Subject>View` | `ZoneView` selects plain or DNSSEC-derived content, not arbitrary history filtering. |
| Execution behavior | `<Operation>Mode` | `ImportMode` selects append/upsert/replace, not row provenance. |
| Reusable governing rules | `<Subject>Policy` | A bundle such as `DnssecPolicy`, not a single-call switch. |
| Change provenance | `<Subject>Source` | `ChangeSource`, distinct from actor and history selection. |
| Resource/destination acted on | `<Operation>Target` | `NotifyTarget`, `LockTarget`, not execution mode. |
| Sort column and direction | `<Subject>SortField`, `SortOrder` | Keep the column separate from ascending/descending. |
| Pagination window only | `PageRequest` | Limit/offset; response metadata is `PaginationResponse`. |

A listing filter may include sorting/pagination beside predicates; do not split
it to enforce suffixes. A pagination-only type remains `PageRequest`.

Fixed outcome enums use `*Result` for an attempt (`TransferResult`, `XfrResult`),
`*Status` for a check (`SecondaryStatus`, `DoctorCheckStatus`, `HealthStatus`), and
`*State` for a lifecycle (`DnssecKeyState`, `DsState`). Their failure variant is
`Failed`, never `Error` or `Fail`; `error` remains the accompanying text.

Variants state the actual predicate/behavior, not an assumed actor (`UserChanges`),
unspecified judgment (`Relevant`), or changeable default.
`VersionFilter::ExcludePastSignerOnly` excludes past versions whose nonempty
journal contains only derived DNSSEC changes; current versions and versions
without journal entries remain. `All` includes every stored version. This filter
is independent of `change_source` and `changed_by`.

Use the same role in fields, parameters, SQL constants, and selectors:
`filter: VersionFilter`, `list_by_filter`, `count_by_filter`.

### Data-access function names

A data-access function performs one query or row operation; a batch may
repeat that operation in chunks to respect backend bind limits. The root
takes the `Db` or the `Transaction` first, matches its backend, and calls the
same-named function in `mysql/`, `postgres/`, or `sqlite/` — and nothing
more: no error mapping, no rule. It lives in the module named for its
entity, and every name is an instance of

```text
<entity>::<operation>[_by_<selector>][_with_<join>][_<predicate>][_tx]

<operation> = get | find | find_<projection>
            | list | list_all | list_<projection>
            | count | count_all | count_<projection>
            | create | create_many | update | update_many | update_<field>
            | delete | delete_many | upsert | prune
```

The operation contains its field, projection, batch, or unfiltered marker;
selectors, joins, predicates, and `_tx` follow in that order. The forms below
define when each is meaningful; add only operations a live caller needs.
`_for_<x>` is banned — the grammar has no slot saying which role `x` plays:
if `x` identifies rows it is `_by_<x>`;
if it is a value being written it is just an argument; a row-selection
comparison is a predicate, and a conditional write rule belongs to the
operation (`upsert`) and its doc comment.

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
- `find` — at most one match of a predicate, without asserting that the
  predicate identifies a unique row; returns `Option`. The doc comment
  states whether any match suffices or an ordering selects one.
- `list` / `count` — a filtered collection / its cardinality. `list_all` is
  the unfiltered form.
- `create` / `update` / `delete` — literal row operations. A partial update
  names the one field it touches, the entity elided as everywhere:
  `update_<field>` (`zone::update_serial_tx`).
- `upsert` — insert-or-update; a conditional rule (the catalog serial
  advancing only when the digest changed) lives in the doc comment, not the
  name.
- `prune` — retention enforcement that may deliberately keep rows the cutoff
  matches (the newest zone version, serial boundaries) — semantics a literal
  `delete_*_older_than` would misdescribe.

`Db::connect` / `begin` / `begin_read`, `Transaction::commit` / `rollback`,
the service's transaction helpers, and connection probes are resource and
lifecycle operations, outside the entity-query grammar.

**Segments:**

- `_many` / entity — the module names the entity, so a function omits it
  and marks the batch form `_many` (`record::create_many_tx`, never
  `record::create_records_tx`).
- `_by_<selector>` — equality keys or a named filter input. Column keys
  are joined with `_and_` and keep `_id` (`list_by_zone_id_and_key_id_tx`).
  The entity's canonical id
  keys are elided, carried by the signature alone: bare `get`/`update`/
  `delete` take the row's own id, bare `list`/`count` the owning zone's id
  (`list_all` stays the unfiltered form). A non-id selector is always named,
  the canonical scope still elided around it (`get_by_serial(zone_id,
  serial)`, `list_by_name_tx(tx, zone_id, name)`), pluralized when it takes
  many values of that one key (`list_by_names_tx`). Every other key path is
  spelled in full: a non-canonical side (`list_by_role_id`,
  `count_by_role_id`, `delete_by_zone_id_tx`), and any key set whose elision
  would leave two functions of one module distinguishable only by their
  signatures — which is why the two-sided policy tables spell everything.
  A non-column selector names the input that defines its predicates:
  `_by_filter` for a predicate selector, whether a struct (`RecordFilter`) or
  an enum (`VersionFilter`). `_by_scope` is reserved for an actual authorization
  scope input. The contract spells the selected rows and retained exceptions.
- `_with_<join>` — the result carries joined data
  (`record::get_with_zone`); never a filter or semi-join.
- `_<predicate>` — a comparison or relation filter as `<subject>_<comparison>`
  (`ds_without_ns`: a DS has no same-owner NS). Serial
  intervals keep their contracts in doc comments — the journal's
  `between_serials` is the IXFR half-open `(from, to]`, the versions'
  `in_serial_range` the closed `[from, to]`.
- Projections — a function returning a column rather than entity rows
  names that column: singular for one value, plural for a collection
  (`record::list_names_tx`, `dnssec_record::list_zone_ids_expiring_within_refresh`). `count_<projection>`
  counts distinct projected values (`count_zone_ids`). The predicate says
  which rows, so no row-set prefix is added.
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

### Service function names

- Parameters follow responsibility: an operation on an existing transaction
  takes `tx` first, then `cx` only if it also needs configuration, metrics,
  or another service resource. Other stateful flows take `cx` first. A
  `Caller`, when required, follows those state parameters, then the request
  and other inputs. Pure helpers take neither `Context` nor `Transaction`
  merely to match a signature. Methods keep `self` before these parameters.
  The transaction lifecycle helpers `begin_tx` / `begin_read_tx` create a
  transaction rather than receive one; `finish_tx` consumes it.
- The functions of `bindizr_service::<entity>` carry the domain semantics
  and omit the entity the module already names (`zone::get_by_name`, not
  `zone::get_zone_by_name`).
  Required reads use `get_*` at the caller-gated boundary and `lookup_*`
  inside a flow that owns authorization; both report a missing required row
  as an error. Internal lookups are private or `pub(crate)` and never
  authorize implicitly: the flow gates the returned row before exposing or
  changing it. The same distinction applies with `_tx`: `get_by_name_tx`
  takes a `Caller`, `lookup_by_name_tx` does not. `find_*` returns `Option`
  when absence is an ordinary outcome, `list_*` a collection, `count_*` a
  count. A `get_*` read may assemble current state from rows and read-only
  probes (`zone::get_status`); a pure calculation is not a read entry point.
  Their authorization follows [Front ends and service flows](#front-ends-and-service-flows) and their contract;
  an optional return does not imply authorization. A domain verb is preferred
  where it says more (`advance_catalog_serial`, `sign_zone_tx`).
- A record mutation that also writes IXFR journal rows says so in the name:
  `*_with_changes_tx`. Preconditions (e.g. "caller already validated the
  rows") belong in the doc comment, not the name.
- A history row — kept so what happened can be read back later — is written
  by `save_*` (`save_version_tx`; `transfer::save_ok`,
  `save_refused`, and `save_failed`, named by the result `XfrResult`
  counts). `track_*` is a
  metrics counter, and `record` is never a verb: it is the noun of
  [Record vocabulary](#record-vocabulary).
- The same data-access verb identifies the same kind of read or write across
  layers; layer contracts decide missing-row errors and authorization. Extra
  domain effects must be named (a raw row delete in `bindizr-db` vs.
  `delete_with_changes_tx` in the service).

### Diagnostic names

The requested operation decides the word, not whether it uses the network.
`status` reports the object's current state and may make read-only probes
needed for that report (`zone status` compares SOA serials). It does not
trigger propagation or change managed state. `check` explicitly exercises
a capability or verifies a named condition: `secondary check` sends a NOTIFY,
and `dnssec check-ds` verifies the parent's delegation, without changing it.
`doctor` aggregates installation diagnostics. A bare `check` covers the
whole object's capability; `check-<part>` a specific condition. Existing
status routes use `GET` and explicit checks use `POST`; those are transport
contracts, not a claim that every check mutates state.

### Helper function names

Read verbs (`get`, `find`, `list`, `count`) describe the same kind of operation
across db, service, and front ends; each layer adds its own missing-row and
authorization contract. Service reads may assemble reports with read-only probes.
Pure calculations never use `get_`; metrics counters use `track_`, not `count_`.
Context-held state uses noun accessors (`cx.config()`, `cx.metrics()`,
`cx.started_at()`) and `set_<field>` for changes. Rows use create/update/delete,
never `set`. `convert_` is not used.

| Responsibility | Vocabulary and boundary |
| --- | --- |
| Representation conversion | Prefer `From` / `TryFrom`; named `as_` / `to_` / `into_` follow [Conversions](#conversions). Use `to_<form>` when the source is evident; `<source>_to_<form>` when the source distinguishes the operation (`labels_to_wire`, `zone_name_to_member_id`). Supplementary representation data follows the same rule. |
| Parse text/wire into a type | Fallible `parse_<thing>`; an infallible reading is `to_` (`to_record_value_request`). |
| Encode/decode bytes | `encode_<thing>` / `decode_<thing>` (`encode_name`). |
| Extract a parsed part | `extract_<thing>` (`extract_ds_record_set`). |
| Present text | `render_<thing>` for multiline human text, `display_<thing>` for a cell, `<thing>_label` for a metric label. |
| Predicate | `is_` / `has_` / `matches_`, returning `bool`; a free predicate names its subject where arguments do not make it evident. Receiver predicates may use other meaningful verb phrases. |
| Field validation | `classify_<thing>` returns core's typed `ParseNameError` without field context; paired `validate_<thing>` phrases it against the field and maps the caller's error. Keep the pair together. |
| Cryptographic verification | `verify_<thing>` returning a result (`verify_tsig`). |
| Diagnostic | `check_<thing>` reports a doctor finding instead of failing; operation-level `check` follows [Diagnostic names](#diagnostic-names). |
| In-memory assembly | `build_<thing>` for payloads/standard values/maps; a module-owned value uses `Type::compute` or `Type::generate`, never free `compute_`. |
| Partitioning | `group_<things>` into a keyed map. |
| Service normalization | `normalize_<thing>` trims, canonicalizes, and validates, returning a canonical value or `ServiceError`. |
| Fresh material | `generate_<thing>` for standard/foreign secret or serial types. |
| Outbound I/O | `send_` one message, `query_` one DNS question, `probe_` reachability/state, `fetch_` a whole artifact (AXFR), `resolve_` names to addresses, `discover_` the parent zone. |
| Disk/stream/output I/O | `load_` / `read_` / `write_`; `print_` is CLI stdout only. |
| Dispatch | `handle_<thing>` for dispatch entry points or routes without an entity; an entity handler uses `<verb>_<entity>`. |
| Flow | `apply_` writes a computed change set; `authenticate_` identifies a caller; `authorize_` gates access. |

Domain actions/lifecycle steps keep their own verbs (`sign_zone`, `escape_label`,
`enqueue_notify`, `run_udp_server`). Do not borrow helper names for side effects:
`build_` does not write state; `to_` does not send.

Nouns are allowed for accessors and pure derivations when a verb adds nothing
(`elapsed_ms`, `record_set_digest`, `promotable_sep_key_ids`, `like_pattern`).
Error/refusal constructors and small HTTP status helpers name the condition
(`ServiceError::unauthorized`, `TransferRefusal::refused`, `unauthorized(message)`).
Message assembly still uses `build_error_response`, not `error_response`.
Foreign-trait names and serde `default_<field>` providers follow their contracts.

Use one name per concept across crates. Do not wrap a function just to rename or
reorder its arguments. A short entry point with an independent contract follows
[Function boundaries](#function-boundaries).

### Construction names

Choose a name from the responsibility, not the return type's implementation:

| Responsibility | Form | Examples |
| --- | --- | --- |
| Assemble a message, payload, or aggregate in memory | `build_<thing>` | `build_question`, `build_page`, `build_json_response` |
| Construct a type's own value | `Type::new`, `Type::parse`, or its lifecycle verb | `DnsMessageBuilder::new`, `ImportPlan::compute`, `Db::connect` |
| Convert the same logical value to another representation | `From` / `TryFrom`, or `as_` / `to_` / `into_` as defined in [Conversions](#conversions) | `OwnerName::to_wire`, `TransferRefusal::into_response` |
| Encode/decode an existing value or frame | `encode_<thing>` / `decode_<thing>` | `encode_tcp_message`, `decode_name_labels` |
| Create a stored entity | `create` in its entity module; `create_<entity>` at a front end | `zone::create`, `create_zone` |

For assembly, use `build_<qualifier>_<thing>` when a qualifier is needed:
`build_signed_error_response`, `build_ixfr_query`. Name the actual artifact:
an error reply is a `response`, while an application error is an `error`.
The same spelling applies to free functions, protocol methods, and test
helpers that assemble wire messages. Small fixture constructors retain the
local names allowed by [Test helpers](#test-helpers) (`test_record`, `axfr_query`).

A function returning an unfinished builder still uses `build_<thing>`:
`build_question(...) -> (u16, AdditionalBuilder<Vec<u8>>)`. Do not use
`<thing>_builder`, `make_<thing>`, or `construct_<thing>` for that operation.
`Builder` belongs in the type name and `builder` may name the local value.
Keep one construction entry point when only finalization differs; the caller
appends optional data or a signature and calls `finish()`. The return type
and a short purpose comment state whether further assembly is possible.
This naming rule does not justify merging different validation, error, or
resource-lifecycle contracts, or adding a wrapper solely to match a name.

### Record vocabulary

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

### Presentation

An enum with a stored, wire, or textual representation has two spellings and no more.
The storage and API form uses `as_str() -> &str` when it can borrow its text, or
`to_text() -> String` when variant data must be formatted.
Serde produces the same form; each such enum's `spells_itself_once` test holds
them together. Rows and metric labels use that form. `Display` is the presentation
form, the one a person reads in a table cell or a message, and every front end
writes the value with `{}` rather than spelling a variant itself. The two coincide
unless the presentation is a DNS mnemonic
(`NSEC3`, `AXFR`), a human phrase (`in sync`), or a notation (`RecordChange`'s
`+`/`-`/`~`); a type whose `Display` nobody reads has none. The CLI's free
`display_<thing>` helpers in `cli/output` render only what no type of ours can own — an
`Option` (`-`), a `bool` (`yes`/`no`), a timestamp, a duration, a truncated cell, and
one cell assembled from several fields — and every command reuses them rather than
formatting inline.

## Code organization and style

### Module layout

A module with file submodules is a directory with `mod.rs`, never a sibling
`message.rs` beside `message/`. Do not change this to the edition-2018 alternative.

- Unit-test modules stay inline below **100 lines**, including their braces.
  At 100 lines, move to `<module>/tests.rs`, make the parent a directory if needed,
  and declare `#[cfg(test)] mod tests;` in `mod.rs`. Import `use super::*;` with the
  other rustfmt-ordered imports. Move tests back inline when deletions put them
  below the threshold.
- Production bodies split only when they exceed **500 lines** outside `#[cfg(test)]`
  **and** contain complete peers of one kind: record types, backends, entity verbs,
  listeners, CLI subcommand groups, resource route groups, protocol sections.
  Split every peer and name files for them; never cut a function, a type's `impl`s,
  or a `match`. One type with its impls, one sequenced flow, or declarations without
  independent logic stays whole regardless of length.

### Visibility

Use only private, `pub(crate)`, and `pub`; never `pub(super)` or `pub(in path)`.
Choose visibility for a coherent group of existing operations or fields, then
use the narrowest scope that serves that group's contract. Current call sites
are evidence of the contract, not a separate visibility rule for each member.

- **`pub` — a cross-crate interface.** Members of the same public API remain
  `pub` even when some currently have only in-crate callers: a value's ordinary
  constructors, representations and predicates; related error constructors;
  or single-item and multi-item forms of the same operation. Examples are
  `OwnerName::is_apex` / `is_same_or_under`, `Rdata::as_bytes` / `into_bytes`,
  `ServiceError` constructors, and `probe_secondary` / `probe_secondaries`.
  A public enum's canonical `as_str` or `to_text` belongs to this value API too.
- **`pub(crate)` — an internal interface.** Apply the same grouping within a
  crate, including shared implementation types and their operations. A private
  module or crate-internal type does not gain `pub` members just to resemble
  a public type; the containing interface limits the group's visibility.
  Re-exports count: a `pub` function in a private implementation module may
  still belong to the public facade that re-exports it.
- **Private — implementation and invariants.** Helpers and state whose access
  is mediated by an operation stay hidden. A shared file, `impl`, name prefix,
  or adjacent declaration alone does not make two members the same API group.

Fields of a plain data carrier form one group at its interface's scope:
`RecordWithZone` fields are `pub`, as `Record` fields are; the adapter's
`Changes` fields are `pub(crate)`. Shared service payload fields are all `pub`.
Constructor-validated storage (`OwnerName`, `Rdata`), resource lifecycle state,
cache internals, and fields requiring controlled mutation stay private.
Mixed visibility is appropriate when fields have these different roles, such
as a private metrics registry beside directly updated public collectors.

Architectural boundaries take precedence over symmetry: `Context::db`, service
`*_tx` operations, authorization-internal lookups, third-party representation
helpers, and test helpers retain their explicitly limited scope. A DTO's
service-only row assembly or encoding helper is not part of its wire contract.
`notify::send_notify` is internal orchestration beneath caller-checked entry
points; public DNS diagnostic operations are a separate group.

Review visibility by naming the group and checking its boundary. Do not narrow
one member solely because a cross-crate caller disappeared, or widen an
internal helper solely to match its neighbors. Explain a non-obvious boundary
once at the owning type or module; routine members need no extra comments.
This grouping permits consistent visibility for existing, live operations;
it does not authorize speculative APIs, unused code, or lint suppression.

### Imports

A `use` never renames: `use domain::base::Record as WireRecord` hides which
name a body reads. A foreign name that collides with one of ours is reached
through its parent module (`inplace::Error`, `domain::base::Ttl`) or, when
the crate uses it in many places, through a `type` alias declared once
beside its kin (`WireName`, `WireRecord` in `dns::dnssec`); a module is
imported as itself (`use bindizr_service::{token, zone}`), never `self as
service`. The one rename is `as _`, for a trait imported only for its
methods (`use std::fmt::Write as _`).

### Comments

- Every named function has one short purpose sentence, including private/nested
  helpers, constructors, methods, trait declarations/implementations, and tests.
  Use Rust `///`, Python docstrings, shell `#`, or Helm template comments.
  Anonymous closures and generated dependency code need no separate comment.
- Read existing comments first and keep one coherent block: purpose, then any
  distinct rationale. Merge overlap instead of adding another purpose sentence.
  Rust docs precede attributes; leave a blank line between documented items.
  Python docstrings start the body, with no stranded explanation above `def`.
  Module-wide explanations belong in module docs; step-specific ones beside the step.
- Preserve reasons, invariants, wire details, and public contracts in one or two
  lines. Keep in-function business/protocol rationale even when the statement is
  obvious (`// Increment zone serial so IXFR consumers can detect this change`).
  Omit walkthroughs, derivable consequences, and enumerations of visible code.
- Shell phase markers (validation, build, installation, cleanup, execution),
  including numbered steps, stay. Test comments state what is verified; overlap
  with the test name is fine. Inside tests, preserve regression/protocol reasons,
  format assumptions, and long E2E phase markers, not a comment per assertion.
- Remove obvious placeholder notes (`id: 0, // Will be set by the database`),
  section labels that only echo the following code, and change-history comments.
  Shell phase markers have the explicit exception above.
- Cite RFCs as `RFC 2181, Section 5.2` or `Sections 5.2–5.3`, never with `§`.

### Lints and live code

Set lint levels only in root `[workspace.lints]`; every crate uses
`[lints] workspace = true`. Keep the set small and the build warning-free without
`#[allow]`. `unsafe_code` is denied. `unreachable_pub` checks reachability through
modules/types, not API grouping or caller counts; apply [Visibility](#visibility)
for those. Do not suppress acronym/naming rules; `clippy::upper_case_acronyms`
stays at its default.

No dead code or `#[allow(dead_code)]`. Add DB functions only for live callers,
never for symmetric `_tx`/non-`_tx` pairs or a complete-looking API. Entity queries
serve the service; `probe_connection` serves offline doctor as a lifecycle operation.
After removing a caller, inspect the next layer: rustc cannot detect an orphaned
cross-crate `pub` facade. Remove a dead DB root function and all three backends together.

### Test names

Name tests `<subject>_<expected_behavior>[_when_<condition>]` in snake_case.
The subject is the operation or contract under test; the rest states an
observable result (`accepts`, `rejects`, `preserves`, `returns`, or another
precise verb). Include conditions that distinguish cases, such as transport,
permissions, or malformed input. Module paths provide context; do not repeat
them unless the subject needs it.

Avoid filler prefixes (`test_`, `verify_`), leading articles, and vague results
such as `works`, `success`, or `lifecycle` alone. A real subject beginning with
`verify_`, such as `verify_tsig`, keeps its operation name. Test helpers follow
their responsibility rules below, not the test-case naming pattern.

Merge tests only when their setup, action, and assertions cover the same
contract. Unit and integration coverage of different boundaries stays separate.

### Test helpers

Test code optimizes for standalone readability. A helper may hide either
**mechanics** (invoke the CLI, build a config, POST a request) or **incidental
fixture defaults**. The test's meaningful data and assertions stay at its
call site: a fixture exposes the fields the case varies as parameters or
local overrides, and does not hide the condition being tested. Extract shared
mechanics only for blocks that are large or repeated many times and change
in lockstep. Small struct-literal fixtures (`test_record()`-style) are allowed
as private helpers in each test file, even when other files have similar
copies; do not collect them into shared fixture modules. Test assertions and
fixture setup may use `unwrap`/`expect`; a test helper's error may be a
`String`, since a failure ends the test instead of entering application logic.

Import/export rules for shared helpers (narrowest visibility that compiles,
never bare `pub`):

1. **Default**: a private `fn` inside the test file that uses it.
2. **Same crate, across modules**: export from the owning module's
   `#[cfg(test)]` tests module with at most `pub(crate)` (e.g.
   `nsupdate/parser/tests.rs::build_minimal_update_with_ztype`). No crate-wide
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

## Documentation and releases

### OpenAPI

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
- `docs/changelog.md` indexes the version files in `docs/changelog/`; the root
  `CHANGELOG.md` points readers to that index. A release's optional notes live
  in `docs/changelog/<version>.md`, without the `v` tag prefix. The file is the
  GitHub release body verbatim, so it keeps that body's form: the title
  `# 🚀 Release: <version>` and the emoji section headings (`📦 Distribution`,
  `📌 Installation (…)`, `⚠️ Breaking Changes`, `✨ New Features`,
  `🧹 Fixes & Improvements`); the date lives in the index alone.

### Web UI

The web UI is the separate `bindizr-ui` repository (a Go backend and a React
app under `ui/`, with a CLAUDE.md of its own), usually checked out beside this
one as `../bindizr-ui`. It tracks this repository through two copies: its
git-ignored `openapi.yaml`, a copy of `docs/openapi.yaml` that
`ui/src/lib/api.ts` and `ui/src/lib/types.ts` must match, and the grant
picker's `ACTION_DESCRIPTIONS` in `types.ts`. A change here that touches
either — a route, a payload, an action's meaning — is finished by a pull
request there, after copying the regenerated spec over. The two repositories
release independently; enabling the chart's optional UI requires setting
`bindizrUi.image.tag` to a compatible image the UI repository has already
pushed.

### Third-party licenses

`about.toml` and `about.hbs` configure cargo-about, which renders the
licenses of every crate the shipped binaries are built from, the vendored
OpenSSL included, into `THIRD_PARTY_LICENSES.html`. The release workflows
generate it and attach it to the GitHub release; it is git-ignored, so
regenerate it locally only to inspect it:

```sh
cargo install cargo-about --locked --features cli
cargo about generate --fail about.hbs -o THIRD_PARTY_LICENSES.html
```

`accepted` in `about.toml` is the license gate: a crate no listed license
covers fails the release, and the answer is a decision about that crate, not
another `accepted` entry.

### Release workflows

`release.yml` publishes what the pushed `v*` tag says, `manual-release.yml`
what `Cargo.toml` and the dispatch inputs say, and `publish-image.yml` the
image tag typed in. Release and Manual Release validate SemVer before building:
check every prerelease identifier, forbid build metadata, and cap the version at 128
characters so a Docker tag can carry it. Publish Image accepts any valid
Docker tag of at most 128 characters, including non-version labels such as
`dev`. Both release workflows use `docs/changelog/<version>.md` as the release
body when that file exists; without it, the release has an empty body. Missing
notes do not block publication. The SemVer format checks are the only
version/tag gates. Build checks and the third-party license gate still apply. `latest` follows the version in the release workflows, as
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
