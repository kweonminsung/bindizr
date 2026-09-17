# Benchmarks

Bindizr measured against PowerDNS Authoritative, Technitium DNS, Knot DNS,
CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and
container limits — the suite lives in
[benchmarks/](https://github.com/kweonminsung/bindizr/blob/main/benchmarks/README.md).
Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each
container capped at 4 CPU / 4 GB.

## No overhead on the query path

![DNS query throughput: Bindizr + BIND9 58,414 QPS, Native BIND9 58,179, CoreDNS 57,669, PowerDNS 55,315, Knot DNS 38,821, Technitium 11,721](assets/benchmarks/b08_query_throughput_light.svg#only-light)
![DNS query throughput: Bindizr + BIND9 58,414 QPS, Native BIND9 58,179, CoreDNS 57,669, PowerDNS 55,315, Knot DNS 38,821, Technitium 11,721](assets/benchmarks/b08_query_throughput_dark.svg#only-dark)

Bindizr never answers a client query — the BIND9 secondaries do. `Bindizr +
BIND9` serves **58,414 QPS against native BIND9's 58,179** (+0.4%, within
run-to-run noise), and Bindizr itself draws no measurable CPU under that load.

## Bulk import

![Bulk import of 10,000 records: Bindizr zone file 103,306 records/sec, Bindizr bulk API 94,331, BIND9 + rndc 35,766, PowerDNS 33,189, Knot DNS 20,855, CoreDNS 13,253, Technitium 8,491](assets/benchmarks/b02_bulk_import_light.svg#only-light)
![Bulk import of 10,000 records: Bindizr zone file 103,306 records/sec, Bindizr bulk API 94,331, BIND9 + rndc 35,766, PowerDNS 33,189, Knot DNS 20,855, CoreDNS 13,253, Technitium 8,491](assets/benchmarks/b02_bulk_import_dark.svg#only-dark)

A 10,000-record zone file imports in **97 ms**; the same records through the
bulk record API take 106 ms. Both paths commit to the database, so the zone
survives a restart and transfers to the secondaries immediately.

## Incremental transfers stay incremental

![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_light.svg#only-light)
![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_dark.svg#only-dark)

A version per SOA serial means an IXFR carries only what changed: **736 B for a
single change in a 100,000-record zone**, where the full zone is 5.5 MB.
PowerDNS answers the same request with the entire zone; Knot DNS and Technitium
track the Bindizr curve.

## Write path

![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.0 ms, PowerDNS 3.0 to 7.8 ms, Knot DNS 16.8 to 21.5 ms, BIND9 + nsupdate 18.0 to 22.8 ms, Bindizr + BIND9 5.0 to 66.7 ms](assets/benchmarks/b03_propagation_light.svg#only-light)
![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.0 ms, PowerDNS 3.0 to 7.8 ms, Knot DNS 16.8 to 21.5 ms, BIND9 + nsupdate 18.0 to 22.8 ms, Bindizr + BIND9 5.0 to 66.7 ms](assets/benchmarks/b03_propagation_dark.svg#only-dark)

A create is acknowledged in **5.0 ms** and answers from the secondaries **66.7
ms** after the call (p95 79 ms, p99 97 ms, no timeouts). Bindizr commits to the
database and propagates by NOTIFY + IXFR, where the integrated servers answer
from their own process as soon as they accept the write.

## Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 356.5 | 350.4 | 318.2 | **13,026.1** | **3.12 ms** | 0.00% |
| Technitium DNS | **8,241.9** | **7,506.1** | **8,559.5** | 9,908.8 | 3.84 ms | 0.00% |
| Knot DNS | 711.4 | **1,044.8** | 710.1 | 1,101.1 | 40.18 ms | 0.00% |
| BIND9 + nsupdate | 370.3 | 862.1 | 358.3 | 1,091.9 | 40.38 ms | 0.00% |
| PowerDNS Authoritative | 80.6 | 68.5 | 76.7 | 2,718.9 | 4.67 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the
per-record write rate — servers that hold the zone in memory do more per second
here. These runs use SQLite; PostgreSQL puts creates at 404/sec against
SQLite's 365. Read
is a management-plane read: an API `GET` where there is an API, a `dig`
subprocess otherwise, so those p95s carry process-spawn cost.

## Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory (stack) |
| --- | --- | --- | --- | --- | --- |
| SQLite | 365.2 | 13,033.9 | 3.09 ms | 0.92 s (108,430/sec) | 203 MB |
| MySQL | 220.5 | 12,213.0 | 4.78 ms | 2.78 s (37,527/sec) | 934 MB |
| PostgreSQL | 404.3 | 11,436.9 | 4.76 ms | 2.51 s (39,831/sec) | 367 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.
Peak memory is the whole stack (Bindizr + BIND9 + the DB server container) at
its highest point, the 100k import; the DB server dominates it — the MySQL
container alone accounts for ~798 MB with its default buffer pool and
`performance_schema` on, against ~228 MB for PostgreSQL. Bindizr's own process
peaks at 26–30 MB there and holds ~11 MB under the CRUD load.

??? note "Software under test"

    | Software | Version |
    | --- | --- |
    | BIND9 | `internetsystemsconsortium/bind9:9.21` |
    | Bindizr | built from source |
    | CoreDNS | `coredns/coredns:1.14.7` |
    | Knot DNS | `cznic/knot:3.6` |
    | MySQL | `mysql:26.7` |
    | PostgreSQL | `postgres:18` |
    | PowerDNS | `powerdns/pdns-auth-49` |
    | Technitium | `technitium/dns-server` |
