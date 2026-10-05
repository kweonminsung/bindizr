# Changelog

Every Bindizr release, newest first. A release pull request writes the
version's section here beside the version bump, and the release workflows
publish that section as the GitHub release body, so a tag without one fails.

## [0.1.0-rc.2] - 2026-10-05

> **Second release candidate.** Every change since **0.1.0-rc.1**: secondaries
> and access rights move into the database, every payload speaks one
> vocabulary, and releases carry their third-party license notice. Clean
> installs only — no upgrade path from rc.1.

### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages for **amd64 and arm64**, the
**multi-arch container image** carrying the ExternalDNS adapter
(`bindizr-external-dns`), and the **Helm chart** on Docker Hub as an OCI
artifact (`oci://registry-1.docker.io/kweonminsung/bindizr-chart`). Every
release now attaches **`THIRD_PARTY_LICENSES.html`**, the notice cargo-about
renders for the crates the binaries are built from, the vendored OpenSSL
included.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-rc.2-1_amd64.deb    # _arm64.deb on arm64
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_rc.2-1.x86_64.rpm    # .aarch64.rpm on arm64
```

### Installation (Helm)

```bash
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.2 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

### Breaking Changes

- **Secondaries are registered at runtime, not configured.** `dns.secondary_addrs`
  is gone; `bindizr secondary create|list|get|update|delete` and `/secondaries`
  register a name, a `host[:port]` address (a hostname is resolved when used),
  `enabled`, and an optional `notify_key_name` whose TSIG key signs every NOTIFY
  to that secondary. NOTIFY fan-out and the unsigned-transfer ACL read the rows
- **Rights belong to roles, not credentials.** An API token or TSIG key names
  exactly one role (`--role`, required) and only authenticates; the role's grants
  decide what it may do. `token grant` / `tsig-key grant` and the
  `/tokens/{name}/grants`, `/tsig-keys/{name}/grants` routes are replaced by
  `role grant|grants|revoke` and `/roles/{name}/grants`. A grant is a zone scope
  (all zones, or one), a set of `<resource>:<action>` actions —
  `zone:read|create|update|delete|transfer`, `record:read|create|update|delete`,
  `dnssec:read|manage`, `secondary:read|manage`, `access:manage` — and record
  name and type constraints. The built-in `admin` role holds every action in
  all zones; the first token is `token create --role admin` over the socket. A
  TSIG-signed transfer needs `zone:transfer`
- **Configuration** (unknown keys are rejected): `dns.notify.after_update` and
  `dns.notify.on_startup` are gone — `batch_ms` alone decides immediate or
  batched NOTIFY and nothing is notified at startup; `dns.transfer_cache.enabled`
  is gone — `max_records = 0` turns the cache off
- **HTTP API vocabulary**: a field naming another entity is `<entity>_name`
  (`zone_name`, `role_name`, `policy_name`, `notify_key_name`), a serial is `u32`,
  a key tag `u16`, a count `u64` named `added`/`deleted`/`unchanged`, a fixed set
  of values is an enum with a schema (`SecondaryStatus`, `TransferResult`,
  `RecordChange`, …), and a response's optional field is `null`, never omitted.
  Every record response carries the caller's `actions` on it
- **A new zone starts with an apex NS record** naming its SOA MNAME, unless the
  request says `apex_ns: false` (`--no-apex-ns`)
- **Schema replaced**: `roles`, `role_grants`, `secondaries`, and `transfers` are
  new; `token_grants` and `tsig_grants` are gone. Rust 1.94 to build

### New Features

- **Secondaries** — `secondary check` (`POST /secondaries/{name}/check`) asks one
  secondary what `doctor` asks all of them: resolution, the catalog serial it
  serves, and a NOTIFY round trip; `secondary transfers` lists what Bindizr
  served each of its addresses, kept in the database so it reads back across
  restarts. Guides for Technitium, Windows Server DNS, YADIFA, Unbound, and
  CoreDNS join BIND9, Knot DNS, NSD, and PowerDNS
- **Roles** — `role create|list|get|delete|grant|grants|revoke` over the CLI,
  the HTTP API, and the daemon socket; `token list --role` / `tsig-key list
  --role`; a role reports its grant, token, and TSIG key counts, and a delete
  refused while credentials hold it names them. `GET /permissions` reports what
  the caller may do, so a client offers only what the server allows
- **Helm chart** — `bind9.service.nodePort` for clusters without a load
  balancer, `bindizr.dns.extraSecondaries` for secondaries outside the chart,
  and named's directory on the persistent volume the chart already claimed
- **Releases** attach the third-party license notice

### Fixes & Improvements

- **Hashing and TLS** run on `ring` alone
- **Internals** — the workspace takes the shape the project's rules describe:
  modules of functions, a `Context` passed by reference, typed errors with
  their causes intact, newtypes for serials, TTLs, key tags, and row ids, and
  one data-carrying `DaemonCommand`. The HTTP API, CLI, and DNS behaviour are
  unchanged by it, error codes and messages included

## [0.1.0-rc.1] - 2026-09-23

> **First release candidate.** Every change since **0.1.0-beta.7**, with the
> configuration, API, and CLI surfaces settled for 0.1.0. Bindizr is now an
> open-source control plane for authoritative DNS: the secondary can be BIND9,
> Knot DNS, NSD, or PowerDNS.

### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages for **amd64 and arm64**, running
the daemon as an unprivileged `bindizr` user with a ready-to-run SQLite config.
The **container image is multi-arch** and still carries the ExternalDNS adapter
(`bindizr-external-dns`). The **Helm chart** stays on Docker Hub as an OCI
artifact (`oci://registry-1.docker.io/kweonminsung/bindizr-chart`).

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-rc.1-1_amd64.deb    # _arm64.deb on arm64
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_rc.1-1.x86_64.rpm    # .aarch64.rpm on arm64
```

### Installation (Helm)

```bash
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-rc.1 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

### Breaking Changes

- **Configuration renamed and regrouped; unknown keys are rejected**:
  `api.authentication_required`, `database.<backend>.url`, `[dns.notify]`,
  `[dns.transfer_cache]`, `dns.nsupdate_tsig_required` (inverted),
  `dns.zone_history_retention_days`, `logging.level`. The `[dnssec]` block is
  gone — signing parameters are DB-backed policies (`bindizr dnssec-policy`)
- **Catalog zone** `catalog.bind` → **`catalog.bindizr`**
  (`dns.catalog_zone_name`); `setup_bind.sh` is replaced by a setup page per
  secondary
- **HTTP API**: token and TSIG *policies* are **grants**
  (`/tokens/{name}/grants`, `/zones/{name}/token-grants`, …); bulk insert is
  `/records/bulk`, import `/zones/{name}/import`, notify `/notify`, rollback
  `/zones/{name}/versions/{serial}/rollback`, the DS check
  `/zones/{name}/dnssec/check-ds`. Listings share one paginated shape, errors
  one `ErrorResponse`, and an ungranted zone answers 404
- **CLI**: `dnssec` / `dnssec-policy` are top-level groups, grants are
  `token grant` / `tsig-key grant`, names are positional, `-c` is the config
  flag, and exit codes name the failure class
- **DNSSEC**: `dnssec enable` requires `--parent-ns-addrs`; NSEC3 is the
  default
- **Names are printable ASCII** (IDN as `xn--` A-labels, lowercased)
- **Schema replaced** (`token_grants`, `tsig_grants`, `catalog_zones`,
  `dnssec_policies`, `dnssec_withdrawals`); Rust 1.94 to build; clean
  installs only — no upgrade path from beta.7

### New Features

- **Any catalog-zone secondary** — BIND9, Knot DNS, NSD, PowerDNS, each
  documented and benchmarked
- **DNSSEC, completed** — DB-backed policies, every RFC 8624 algorithm,
  NSEC3, scheduled ZSK rollovers, parent-DS verification and unattended
  promotion, algorithm rollovers, RFC 8078 DS withdrawal, BIND key-file
  import/export, richer status, Prometheus metrics
- **TSIG-authenticated zone transfers** and **HTTPS for the API**
- **API tokens over HTTP** — create, list, delete, `GET /tokens/self`;
  read-only grants
- **Zone migration** — `zone import --from-server` pulls a zone over AXFR;
  `--create` builds it from the file's SOA
- **Records** — DNAME and NAPTR, set-wide deletes, `--dry-run` previews on
  every change, versions record their author, `zone update --enabled false`
- **Daemon** — config reload without restart, graceful SIGTERM, configurable
  maintenance interval, JSON logs
- **CLI** — `-o json|yaml|table` everywhere, `ls`/`rm` aliases, colorized
  diffs, `man`, completions, `doctor -o json`

### Fixes & Improvements

- **UDP listener no longer serves one query at a time**; both listeners are
  bounded
- **Correctness** — MX/SRV priority stored, TXT shape preserved, NAPTR
  validated as BIND does, owner-only daemon socket, NOTIFY delivered across
  shutdown, one deadline per AXFR
- **Performance** — scoped listings narrowed in SQL, journal/version indexes,
  narrower nsupdate locks, right-sized SQLite bulk inserts, cached ACL
  lookups

## [0.1.0-beta.7] - 2026-08-27

### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages continue to be supported, and the
Helm chart continues to be published as an OCI artifact on Docker Hub
(`oci://registry-1.docker.io/kweonminsung/bindizr-chart`).

The **ExternalDNS webhook provider adapter ships inside the same container
image** as a second binary (`bindizr-external-dns`); no separate image to pull.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.7-1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_beta.7-1.x86_64.rpm
```

### Installation (Helm)

```bash
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

### Breaking Changes

- **`bindizr zone snapshot …` is now `bindizr zone version …`** (`list` / `get`
  / `diff` / `rollback`), and the HTTP surface moved to
  `GET /zones/{name}/versions`
- **Config keys renamed**: `dns.apply_mode` → **`dns.notify_mode`** and
  `dns.apply_batch_ms` → **`dns.notify_batch_ms`**; the old names are not
  accepted
- **Schema replaced**: `zone_changes` and `zone_soa_history` are gone, superseded
  by `zone_journal` and `zone_versions`; `dnssec_keys`, `dnssec_records`, and
  `zone_token_policies` are new
- Clean installs only — there is no upgrade path from beta.6

### New Features

- **DNSSEC** — end-to-end online zone signing with CSK/KSK/ZSK, ECDSAP256SHA256 and Ed25519, NSEC/NSEC3, DS generation, scheduled re-signing, and key rollover
- **ExternalDNS webhook provider** — `bindizr-external-dns` lets Kubernetes Services and Ingresses manage bindizr records, with token zone grants acting as the domain filter
- **Per-zone API token policies** — restrict tokens by zone, record-name pattern, and record type
- **New record types** — added CAA, SSHFP, TLSA, DS, and delegation NS records

### Fixes & Improvements

- **Safer DNS name handling** — label-aware comparisons now correctly handle escaped dots, wildcard policies, zone matching, and apex records
- **Performance** — improved database transaction handling, SQLite WAL/pooling, record indexes, SQL-side filtering, and reduced allocations on read/write paths
- **Correctness** — tightened record-size and SOA serial validation, improved nsupdate error responses, preserved TXT whitespace, relaxed valid CAA whitespace, and fixed several edge-case rollback/cache issues

## [0.1.0-beta.6] - 2026-07-31

### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages continue to be supported.

The **Helm chart is now distributed as an OCI artifact on Docker Hub**
(`oci://registry-1.docker.io/kweonminsung/bindizr-chart`); the GitHub Pages
`helm repo add` repository has been discontinued.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.6-1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_beta.6-1.x86_64.rpm
```

### Installation (Helm)

```bash
helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.6 \
  --set bindizr.database.existingSecret=bindizr-db-secret
```

### Breaking Changes

- The Helm chart moved to **Docker Hub OCI** and was renamed **`bindizr-stack` → `bindizr-chart`**; the classic GitHub Pages chart repository no longer receives releases, and rendered resource names change with the new chart name
- `setup_bind.sh` now requires the bindizr address to be an **IPv4 literal** and only replaces the catalog-zone block it wrote itself; manually configured zones are preserved and reported instead of overwritten
- Clean installs only — there is no upgrade path from beta.5

### New Features

- **Prometheus metrics** — unauthenticated `GET /metrics` (on by default via `api.metrics_enabled`) exposing build info, database liveness, zone/record totals, HTTP request counts and latency labeled by route pattern, AXFR/IXFR outcomes, NOTIFY delivery attempts, nsupdate results, and zone serial bumps
- **Monitoring example** — a ready-to-run Prometheus + Grafana compose stack with a pre-provisioned *Bindizr Overview* dashboard (`examples/monitoring/`)
- **Daemon lifecycle commands** — `bindizr status`, `bindizr stop`, and `bindizr restart` (in-place re-exec that keeps the PID, so systemd/docker supervision stays attached)
- **`bindizr doctor`** — end-to-end installation health check covering config, daemon, API, database, DNS listener, and secondary sync
- **`bindizr config check/list/get`** — validate a configuration file offline and inspect the running daemon's loaded configuration by dotted key
- **`/health`** — unauthenticated liveness probe for load balancers and orchestrators, backed by a bounded database round-trip
- **`setup_bind.sh` host/port arguments** — point BIND at a non-default bindizr address (`... | sudo bash -s -- 10.0.0.5 5353` or `BINDIZR_DNS_HOST`/`BINDIZR_DNS_PORT`), with strict input validation and idempotent re-runs via a managed marker block

### Fixes & Improvements

- `bindizr doctor`, the health probe, and secondary-address resolution are strictly time-bounded so probes cannot hang on a wedged database or resolver

## [0.1.0-beta.5] - 2026-07-27

> **0.1.0-beta.4 was skipped.** The version was bumped internally but never
> published, so this release rolls up every change since **0.1.0-beta.3**.

### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages continue to be supported.
Additional package formats may be added in future releases.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.5-1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_beta.5-1.x86_64.rpm
```

### Breaking Changes

- CLI commands restructured from verb-noun to **noun-verb** (`bindizr zone notify`, `bindizr record update`)
- nsupdate authentication moved from a single global TSIG key to **reusable keys + per-zone policies**
- SOA serials are now a **plain monotonic counter starting at 1**, no longer date-based
- Record read/update/delete API endpoints now require `zone_name`
- Non-UTF-8 TXT input is rejected at the API boundary (stored octets are still preserved on import/export)
- Clean installs only — there is no upgrade path from beta.3

### New Features

- **RFC 2136 dynamic updates (nsupdate)** over the DNS listener, authenticated with TSIG — standalone reusable keys, per-zone policies scoped by record-name pattern and record type, and optional global keys that may update every zone
- **Zone snapshots** — every SOA serial keeps a snapshot: list, inspect, diff two serials, and roll a zone back (`bindizr zone snapshot list/get/diff/rollback`)
- **Bulk record insert and zone-file import** through both the API and the CLI (the CLI also accepts YAML), with `--preview` / dry-run `+/-/~` diffs before anything is applied
- **Zone export** to BIND master-file text, the exact inverse of import
- **Secondary sync status** — `bindizr zone status <ZONE>` and the matching API endpoint report how far each secondary has caught up
- **Helm chart** (`bindizr-stack`) deploying Bindizr, BIND9 secondary pods, and optional bundled MySQL/PostgreSQL, with TSIG and bindizr-ui options; published to Artifact Hub
- **Docker Compose stacks** for MySQL and PostgreSQL deployments, defaulting to PostgreSQL
- **Async apply mode** that decouples writes from reload/NOTIFY, coalescing queued NOTIFYs within a configurable batch window
- **Pagination and filtering** on the list APIs, plus case-insensitive record search
- **Serial-keyed AXFR zone cache** with LRU eviction, and a single-query IXFR snapshot path
- **OpenAPI documentation** generated at compile time with `utoipa` and published to GitHub Pages

### Fixes & Improvements

- Reorganized the project into a **Rust workspace** of six crates (`core`, `db`, `dns`, `service`, the binary, and an external e2e suite)
- Replaced hand-rolled DNS wire walkers with the `domain` crate across queries, XFR answers, nsupdate parsing, and TSIG
- Serial safety: the seed serial is capped at zone creation, zone mutations are rejected once the serial reaches `i32::MAX`, and the bump is atomic
- Transaction correctness: zone→record lock order preserved, zone updates serialized, constraint-violation races mapped, partial updates merged inside the transaction
- Error handling: fine-grained error codes with prefix-free messages and CLI hints, unified 404 for a missing zone, 413 instead of 500 for oversized bodies, and no more daemon/CLI panics
- Performance: multi-row batched bulk insert, sargable conflict lookups with a `records(zone_id, name)` index, host-sized connection pools, and far fewer allocations on the write path

## [0.1.0-beta.3] - 2026-03-23


### Distribution

**Debian (.deb)** and **RPM (.rpm)** packages continue to be supported.
Additional package formats may be added in future releases.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.3-1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_beta.3-1.x86_64.rpm
```

### New Features
- Switched core architecture from file-based + rndc to an XFR-driven model (AXFR/IXFR + catalog zones)
- Added automatic IXFR → AXFR fallback for reliable synchronization
- Improved catalog zone compatibility with BIND9
- Strengthened DNS compliance and data consistency

### Fixes & Improvements
- Removed zone and record history APIs
- Various stability and consistency improvements

## [0.1.0-beta.2] - 2025-10-01

### Distribution

**Debian packages (`.deb`)** and **RPM packages (`.rpm`)** are now supported.
Additional package formats may be added in future releases.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.2-1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0_beta.2-1.x86_64.rpm
```

### New Features

- Switched from fork-based daemonization to native Linux systemd service management

- Improved serializer performance

- Removed unnecessary configuration file entries

## [0.1.0-beta.1] - 2025-09-08

### Distribution

**Debian packages (`.deb`)** and **RPM packages (`.rpm`)** are now supported.
Additional package formats may be added in future releases.

### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-beta.1_amd64.deb
```

### Installation (RHEL/CentOS/Fedora)

```bash
rpm -i bindizr-0.1.0.beta.1-1.x86_64.rpm
```

### New Features

- Database driver migration: Replaced MySQL driver with sqlx, adding support for PostgreSQL and SQLite.

- Error handling improvements: Introduced more detailed error handling for better debugging and reliability.

## [0.1.0-alpha.1] - 2025-06-24

> ⚠️ **Warning:** This is an early **alpha pre-release** version.
> Features, configuration formats, and APIs may change without notice, and stability is not guaranteed.

### Distribution

Currently, only **Debian packages (`.deb`)** are supported.
Support for other package formats (e.g., RPM) will be added in future releases.


### Installation (Debian/Ubuntu)

```bash
dpkg -i bindizr_0.1.0-alpha.1_amd64.deb
