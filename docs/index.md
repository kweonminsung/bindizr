---
hide:
  - navigation
---

<div class="bindizr-hero" markdown>

# ![Bindizr](assets/bindizr_horizontal.png)

DNS Synchronization Service for BIND9

</div>

**Bindizr** is a Rust-based DNS control plane that manages zones and records via an HTTP API or CLI, stores data in a database backend (MySQL, PostgreSQL, or SQLite), and propagates changes to BIND9 secondary servers via AXFR/IXFR using DNS Catalog Zones.

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Deploy it](deployment/index.md)**

    Helm, Docker Compose, or a package install on a VM.

-   :material-tune: **[Configure it](configuration.md)**

    Every option in `bindizr.conf.toml` and its environment-variable form.

-   :material-console: **[Drive it](cli/index.md)**

    Zones, records, versions, access control, and DNSSEC from the CLI.

-   :material-api: **[Automate it](http-api/index.md)**

    Token-authenticated HTTP API with an OpenAPI reference.

</div>

## Concepts

![Bindizr concepts](assets/concepts.png){ .bindizr-concepts width="462" }

**Control Plane**
:   Manage DNS zones and records through HTTP API or CLI commands. All changes are stored in the database (MySQL, PostgreSQL, or SQLite).

**XFR Server**
:   Built-in AXFR (full zone transfer) and IXFR (incremental zone transfer) server that serves zone data to secondary DNS servers. SOA serial numbers are automatically incremented on each change.

**Catalog Zones**
:   Bindizr uses DNS Catalog Zones (RFC 9432) to automatically propagate zone configuration to BIND9 secondary servers. When you create or delete a zone via the API/CLI, BIND9 automatically discovers and configures it without manual intervention.

**Secondary DNS Servers**
:   Standard BIND9 (or any RFC-compliant DNS server) instances configured as secondaries. They automatically discover zones through the catalog zone, pull zone updates from Bindizr's XFR server via zone transfer, and respond to DNS queries from clients.

## Features

- **Zone and Record Management**: Full CRUD over zones and records through the HTTP API or CLI, including bulk inserts, BIND master-file import/export, and dry-run diff previews.

- **Multiple Database Backends**: Store DNS data in MySQL, PostgreSQL, or SQLite.

- **Zone Transfers (AXFR/IXFR)**: Serve full and incremental zone transfers to secondaries, with automatic SOA serial management and an optional per-serial zone cache.

- **Automatic Zone Provisioning**: DNS Catalog Zones (RFC 9432) let BIND9 secondaries discover created and deleted zones without configuration changes.

- **DNS NOTIFY**: Notify secondaries after each change, with configurable retries and timeouts, plus a sync/async apply mode that batches NOTIFYs under load.

- **nsupdate (Dynamic Update)**: RFC 2136 dynamic updates with TSIG-signed requests, managed TSIG keys, and per-zone update policies.

- **DNSSEC**: Named signing policies (algorithm, NSEC/NSEC3, CSK or KSK/ZSK, timing), automatic signing and re-signing, key rollovers (ZSK rolls scheduled and promoted automatically, CSK/KSK rolls confirmed by the operator), BIND-format key import/export, and RFC 8078 DS withdrawal — see [DNSSEC](dnssec.md).

- **Zone Versions**: A version per serial, with diffs between serials and rollback to a previous serial.

- **Observability**: Health probe endpoint, Prometheus metrics at `/metrics`, and `bindizr doctor` end-to-end diagnostics.

## Performance

Bindizr never answers a client query — the BIND9 secondaries do. It owns the
zone data and the transfer path, so putting it in front of BIND9 costs
[nothing on the query path](benchmarks.md#no-overhead-on-the-query-path):
`Bindizr + BIND9` serves **57,466 QPS against native BIND9's 57,674**.

## License

Bindizr is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
