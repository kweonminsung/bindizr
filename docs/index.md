---
hide:
  - navigation
---

<div class="bindizr-hero" markdown>

# ![Bindizr](assets/bindizr_horizontal.png)

Open-source control plane for authoritative DNS

</div>

**Bindizr** manages DNS zones and records through an HTTP API or CLI.
It stores them in MySQL, PostgreSQL, or SQLite and sends changes to BIND,
Knot DNS, NSD, PowerDNS, Technitium, Windows Server DNS, and
[other secondaries](secondaries/index.md). Those servers answer your clients'
DNS queries.

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Deploy it](deployment/index.md)**

    Install on Kubernetes, Docker Compose, or a host, then query your first zone.

-   :material-tune: **[Configure it](configuration.md)**

    Every option in `bindizr.conf.toml` and its environment-variable form.

-   :material-console: **[Use the CLI](cli/index.md)**

    Zones, records, versions, access control, and DNSSEC from the CLI.

-   :material-api: **[Automate it](http-api/index.md)**

    Token-authenticated HTTP API with an OpenAPI reference.

</div>

## Concepts

[![Bindizr control plane and secondary DNS servers](assets/concepts.png){ .bindizr-concepts width="720" }](assets/concepts.png)

**Control Plane**
:   The HTTP API and CLI manage zones and records stored in the database.

**XFR Server**
:   Sends a whole zone (AXFR) or just its changes (IXFR) to secondaries.
    Each change advances the zone's SOA serial number.

**Catalog Zones**
:   Tell secondaries which zones to serve. Creating or deleting a zone in
    Bindizr updates the catalog automatically (RFC 9432).

**Secondary DNS Servers**
:   Discover zones from the catalog, pull their records, and answer client
    queries. See [Secondary Servers](secondaries/index.md) for setup.

## Features

- **[Zones and records](cli/zones.md)**: Bulk changes, zone-file import/export,
  dry-run previews, version diffs, and rollback.
- **[Dynamic updates](cli/nsupdate.md)**: RFC 2136 updates authenticated with TSIG keys.
- **[Access control](cli/access-control.md)**: Roles limit API tokens and TSIG keys
  by zone, action, record name, and type.
- **[DNSSEC](dnssec/index.md)**: Automatic signing, signature renewal, key rollover,
  and BIND-format key import/export.
- **[ExternalDNS](external-dns.md)**: Turn Kubernetes Service and Ingress hostnames
  into DNS records.
- **[Observability](http-api/metrics.md)**: Prometheus metrics, health probes,
  text or JSON logs, and CLI diagnostics.

## Performance

In the [benchmark runs](benchmarks.md#no-overhead-on-the-query-path),
Bindizr + BIND served **59,397 queries/s**, compared with **59,904 queries/s**
for BIND alone. Client queries go directly to the secondary.

## License

Bindizr is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
