# Benchmarks

Bindizr measured against PowerDNS Authoritative, Technitium DNS, Knot DNS,
CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and
container limits — the suite lives in
[benchmarks/](https://github.com/kweonminsung/bindizr/blob/main/benchmarks/README.md).
Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each
container capped at 4 CPU / 4 GB.

## No overhead on the query path

![DNS query throughput: Native BIND9 57,674 QPS, Bindizr + BIND9 57,466, CoreDNS 54,306, PowerDNS 51,718, Knot DNS 36,353, Technitium 10,978](assets/benchmarks/b08_query_throughput_light.svg#only-light)
![DNS query throughput: Native BIND9 57,674 QPS, Bindizr + BIND9 57,466, CoreDNS 54,306, PowerDNS 51,718, Knot DNS 36,353, Technitium 10,978](assets/benchmarks/b08_query_throughput_dark.svg#only-dark)

Bindizr never answers a client query — the BIND9 secondaries do. `Bindizr +
BIND9` serves **57,466 QPS against native BIND9's 57,674** (−0.4%, within
run-to-run noise), and Bindizr itself draws no measurable CPU under that load.

## Bulk import

![Bulk import of 10,000 records: Bindizr zone file 114,440 records/sec, Bindizr bulk API 90,058, BIND9 + rndc 88,996, PowerDNS 32,875, Knot DNS 20,599, CoreDNS 13,275, Technitium 8,168](assets/benchmarks/b02_bulk_import_light.svg#only-light)
![Bulk import of 10,000 records: Bindizr zone file 114,440 records/sec, Bindizr bulk API 90,058, BIND9 + rndc 88,996, PowerDNS 32,875, Knot DNS 20,599, CoreDNS 13,275, Technitium 8,168](assets/benchmarks/b02_bulk_import_dark.svg#only-dark)

A 10,000-record zone file imports in **88 ms**; the same records through the
bulk record API take 111 ms. Both paths commit to the database, so the zone
survives a restart and transfers to the secondaries immediately.

## Incremental transfers stay incremental

![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_light.svg#only-light)
![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_dark.svg#only-dark)

A snapshot per SOA serial means an IXFR carries only what changed: **736 B for a
single change in a 100,000-record zone**, where the full zone is 5.5 MB.
PowerDNS answers the same request with the entire zone; Knot DNS and Technitium
track the Bindizr curve.

## Write path

![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.0 ms, PowerDNS 3.0 to 7.6 ms, Knot DNS 16.8 to 21.5 ms, BIND9 + nsupdate 17.5 to 22.0 ms, Bindizr + BIND9 6.6 to 66.3 ms](assets/benchmarks/b03_propagation_light.svg#only-light)
![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.0 ms, PowerDNS 3.0 to 7.6 ms, Knot DNS 16.8 to 21.5 ms, BIND9 + nsupdate 17.5 to 22.0 ms, Bindizr + BIND9 6.6 to 66.3 ms](assets/benchmarks/b03_propagation_dark.svg#only-dark)

A create is acknowledged in **6.6 ms** and answers from the secondaries **66.3
ms** after the call (p95 76 ms, p99 80 ms, no timeouts). Bindizr commits to the
database and propagates by NOTIFY + IXFR, where the integrated servers answer
from their own process as soon as they accept the write.

## Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 192.2 | 175.7 | 180.9 | **12,785.0** | **3.30 ms** | 0.00% |
| Technitium DNS | **8,062.4** | **7,402.3** | **8,178.1** | 9,747.1 | 3.94 ms | 0.00% |
| Knot DNS | 656.4 | 936.1 | 650.0 | 1,041.4 | 43.06 ms | 0.00% |
| BIND9 + nsupdate | 367.2 | 788.5 | 357.8 | 1,033.4 | 43.64 ms | 0.00% |
| PowerDNS Authoritative | 78.8 | 67.3 | 77.8 | 2,672.6 | 4.79 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the
per-record write rate — servers that hold the zone in memory do more per second
here. These runs use SQLite; PostgreSQL raises creates from 187 to 522/sec. Read
is a management-plane read: an API `GET` where there is an API, a `dig`
subprocess otherwise, so those p95s carry process-spawn cost.

## Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory (stack) |
| --- | --- | --- | --- | --- | --- |
| SQLite | 187.0 | 12,619.7 | 3.29 ms | 1.01 s (99,527/sec) | 138 MB |
| MySQL | 223.7 | 11,616.3 | 4.94 ms | 2.29 s (43,673/sec) | 1,025 MB |
| PostgreSQL | 522.1 | 11,117.3 | 4.88 ms | 2.12 s (47,182/sec) | 331 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.
Peak memory is the whole stack (Bindizr + BIND9 + the DB server container);
the DB server dominates it — MySQL idles near 450 MB with its default buffer
pool and `performance_schema` on, while Bindizr's own process stays small on
every backend.

??? note "Software under test"

    | Software | Version |
    | --- | --- |
    | BIND9 | `internetsystemsconsortium/bind9:9.21` |
    | Bindizr | built from source |
    | CoreDNS | `coredns/coredns:1.14.6` |
    | Knot DNS | `cznic/knot:3.5` |
    | MySQL | `mysql:26.7` |
    | PostgreSQL | `postgres:18` |
    | PowerDNS | `powerdns/pdns-auth-49` |
    | Technitium | `technitium/dns-server` |
