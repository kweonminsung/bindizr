<div align="center">
<p align="center">
    <img src="docs/assets/bindizr_horizontal.png" width="400px" alt="Bindizr">
</p>

DNS Synchronization Service for BIND9

<p>
    <a href="https://github.com/netbirdio/netbird/blob/main/LICENSE">
        <img src="https://img.shields.io/badge/license-Apache 2.0-blue" />
    </a>
    <a href="https://github.com/kweonminsung/bindizr/actions/workflows/ci.yml">
        <img src="https://github.com/kweonminsung/bindizr/actions/workflows/ci.yml/badge.svg" />
    </a>
    <br>
    <a href="https://app.codacy.com/gh/kweonminsung/bindizr/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade">
        <img src="https://app.codacy.com/project/badge/Grade/29665b2525ce453bb78429b13ec8ede9" />
    </a>
</p>

**[Documentation](https://kweonminsung.github.io/bindizr/) &nbsp;·&nbsp; [API Reference](https://kweonminsung.github.io/bindizr/api/)**

</div>

**Bindizr** is a Rust-based DNS control plane that manages zones and records via an HTTP API or CLI, stores data in a database backend (MySQL, PostgreSQL, or SQLite), and propagates changes to BIND9 secondary servers via AXFR/IXFR using DNS Catalog Zones.

&nbsp;<img src="docs/assets/concepts.png" width="462px" alt="Bindizr control plane and XFR server feeding BIND9 secondaries, which answer client queries">

Bindizr owns the zone data and the transfer path; standard BIND9 secondaries discover zones through the catalog zone (RFC 9432) and answer client queries. Adding it in front of BIND9 costs nothing on the query path — `Bindizr + BIND9` serves **57,466 QPS against native BIND9's 57,674**.

## Features

- **Zone and Record Management** — full CRUD through the HTTP API or CLI, including bulk inserts, BIND master-file import/export, and dry-run diff previews.
- **Multiple Database Backends** — MySQL, PostgreSQL, or SQLite.
- **Zone Transfers (AXFR/IXFR)** — automatic SOA serial management and an optional per-serial zone cache.
- **Automatic Zone Provisioning** — DNS Catalog Zones (RFC 9432) let secondaries discover created and deleted zones without configuration changes.
- **DNS NOTIFY** — configurable retries and timeouts, plus an optional batching window that collapses a burst into one NOTIFY per zone.
- **nsupdate (Dynamic Update)** — RFC 2136 dynamic updates with TSIG-signed requests, managed keys, and per-zone grants.
- **DNSSEC** — named signing policies, automatic signing and re-signing, automatic ZSK and operator-confirmed CSK/KSK rollovers, BIND-format key import/export, and a parent-DS check before a zone goes insecure.
- **ExternalDNS Provider** — a webhook adapter that lets Kubernetes ExternalDNS manage records in opted-in zones through the authenticated API.
- **Zone Versions** — a version per serial, with diffs between serials and rollback.
- **Observability** — health probe, Prometheus metrics at `/metrics`, text or JSON logs, and `bindizr status` / `bindizr doctor` diagnostics.

## Roadmap

- **Per-zone ACLs** — transfer and SOA access is one server-wide list today.
  Scoping it per zone lets one deployment serve secondaries that each hold
  part of the catalog.
- **Secondaries managed at runtime** — the secondary list is a config field, so
  adding one takes a restart. Moving it into the database puts it behind the
  API and CLI, like zones, tokens, and signing policies already are.

## Quick Start

Pick one. Each is walked through in full on the
[documentation site](https://kweonminsung.github.io/bindizr/).

### Kubernetes

The chart can bring its own PostgreSQL for a first look; in production, point it
at your database instead.

```bash
$ helm install bindizr oci://registry-1.docker.io/kweonminsung/bindizr-chart \
  --version 0.1.0-beta.7 --set postgresql.enabled=true
```

### Docker Compose

Builds the image from the working tree and brings up Bindizr, PostgreSQL, and
two BIND9 secondaries on one host.

```bash
$ docker compose -f examples/compose/docker-compose.yml up -d --build
```

### Docker Swarm

Brings up Bindizr, PostgreSQL, and BIND9 on an overlay network.

```bash
$ docker stack deploy -c examples/swarm/docker-compose.yml bindizr
```

### Package install

```bash
$ sudo dpkg -i bindizr_*_amd64.deb    # Debian, Ubuntu (bindizr_*_arm64.deb on arm64)
$ sudo rpm -i bindizr-*.x86_64.rpm    # Fedora, CentOS, RHEL (bindizr-*.aarch64.rpm on arm64)
```

The package runs on SQLite out of the box and serves zone transfers on port
5300, leaving 53 to BIND9. Point BIND9 at the catalog zone with the bundled
script, then start.

```bash
$ sudo /usr/share/bindizr/setup_bind.sh && sudo systemctl restart named   # bind9 on Debian
$ sudo systemctl start bindizr
```

---

However you installed it, this checks the whole path end to end:

```bash
$ sudo bindizr doctor
```

The daemon's control socket is owner-only, so the CLI runs as the user the
daemon runs as: `sudo` for a package install, `docker exec` / `kubectl exec`
into the container for Compose and Helm.

API authentication is on by default for Helm and package installs — the Compose
stack ships with it off. Create a token before calling the API:

```bash
$ sudo bindizr token create --name admin --global
```

## Documentation

Deployment, configuration, the CLI, the HTTP API, and the benchmarks are all at
**[kweonminsung.github.io/bindizr](https://kweonminsung.github.io/bindizr/)**.

## Contributing

Bug reports, documentation fixes, and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the test and lint commands, and the project conventions a review will check against.

## License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
