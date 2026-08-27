# Benchmarks

Bindizr measured against PowerDNS Authoritative, Technitium DNS, Knot DNS,
CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and
container limits — the suite lives in
[benchmarks/](https://github.com/kweonminsung/bindizr/blob/main/benchmarks/README.md).
Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each
container capped at 4 CPU / 4 GB.

## No overhead on the query path

![DNS query throughput: CoreDNS 57,782 QPS, Bindizr + BIND9 57,656, Native BIND9 57,310, PowerDNS 54,704, Knot DNS 38,770, Technitium 11,545](assets/benchmarks/b08_query_throughput_light.svg#only-light)
![DNS query throughput: CoreDNS 57,782 QPS, Bindizr + BIND9 57,656, Native BIND9 57,310, PowerDNS 54,704, Knot DNS 38,770, Technitium 11,545](assets/benchmarks/b08_query_throughput_dark.svg#only-dark)

Bindizr never answers a client query — the BIND9 secondaries do. `Bindizr +
BIND9` serves **57,656 QPS against native BIND9's 57,310** (+0.6%, within
run-to-run noise), and Bindizr itself draws no measurable CPU under that load.

## Bulk import

![Bulk import of 10,000 records: Bindizr zone file 110,820 records/sec, Bindizr bulk API 92,212, BIND9 + rndc 35,880, PowerDNS 30,669, Knot DNS 16,973, CoreDNS 12,640, Technitium 8,505](assets/benchmarks/b02_bulk_import_light.svg#only-light)
![Bulk import of 10,000 records: Bindizr zone file 110,820 records/sec, Bindizr bulk API 92,212, BIND9 + rndc 35,880, PowerDNS 30,669, Knot DNS 16,973, CoreDNS 12,640, Technitium 8,505](assets/benchmarks/b02_bulk_import_dark.svg#only-dark)

A 10,000-record zone file imports in **90 ms**; the same records through the
bulk record API take 108 ms. Both paths commit to the database, so the zone
survives a restart and transfers to the secondaries immediately.

## Incremental transfers stay incremental

![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_light.svg#only-light)
![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_dark.svg#only-dark)

A version per SOA serial means an IXFR carries only what changed: **736 B for a
single change in a 100,000-record zone**, where the full zone is 5.5 MB.
PowerDNS answers the same request with the entire zone; Knot DNS and Technitium
track the Bindizr curve.

## Write path

![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.1 ms, PowerDNS 3.0 to 7.9 ms, Knot DNS 17.0 to 21.7 ms, BIND9 + nsupdate 17.9 to 22.8 ms, Bindizr + BIND9 4.5 to 64.9 ms](assets/benchmarks/b03_propagation_light.svg#only-light)
![Median record-create latency from API call to DNS visibility: Technitium 0.7 to 5.1 ms, PowerDNS 3.0 to 7.9 ms, Knot DNS 17.0 to 21.7 ms, BIND9 + nsupdate 17.9 to 22.8 ms, Bindizr + BIND9 4.5 to 64.9 ms](assets/benchmarks/b03_propagation_dark.svg#only-dark)

A create is acknowledged in **4.5 ms** and answers from the secondaries **64.9
ms** after the call (p95 76 ms, p99 94 ms, no timeouts). Bindizr commits to the
database and propagates by NOTIFY + IXFR, where the integrated servers answer
from their own process as soon as they accept the write.

## Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 368.9 | 357.5 | 353.4 | **12,705.1** | **3.20 ms** | 0.00% |
| Technitium DNS | **8,185.6** | **7,309.7** | **8,280.3** | 9,935.0 | 3.75 ms | 0.00% |
| Knot DNS | 701.7 | **1,045.6** | 720.2 | 1,094.5 | 40.30 ms | 0.00% |
| BIND9 + nsupdate | 379.0 | 846.3 | 389.0 | 1,092.3 | 40.42 ms | 0.00% |
| PowerDNS Authoritative | 81.2 | 64.9 | 78.0 | 2,790.7 | 4.53 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the
per-record write rate — servers that hold the zone in memory do more per second
here. These runs use SQLite; PostgreSQL puts creates at 406/sec against
SQLite's 365. Read
is a management-plane read: an API `GET` where there is an API, a `dig`
subprocess otherwise, so those p95s carry process-spawn cost.

## Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory (stack) |
| --- | --- | --- | --- | --- | --- |
| SQLite | 365.1 | 13,031.0 | 3.09 ms | 0.95 s (105,221/sec) | 181 MB |
| MySQL | 222.1 | 12,066.0 | 4.83 ms | 2.64 s (37,925/sec) | 1,038 MB |
| PostgreSQL | 405.8 | 11,634.4 | 4.73 ms | 2.47 s (40,567/sec) | 349 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.
Peak memory is the whole stack (Bindizr + BIND9 + the DB server container);
the DB server dominates it — the MySQL container alone accounts for ~515 MB
with its default buffer pool and `performance_schema` on, against ~88 MB for
PostgreSQL, while Bindizr's own process stays at ~10 MB.

??? note "Software under test"

    | Software | Version |
    | --- | --- |
    | BIND9 | `internetsystemsconsortium/bind9:9.21` |
    | Bindizr | built from source |
    | CoreDNS | `coredns/coredns:1.14.7` |
    | Knot DNS | `cznic/knot:3.5` |
    | MySQL | `mysql:26.7` |
    | PostgreSQL | `postgres:18` |
    | PowerDNS | `powerdns/pdns-auth-49` |
    | Technitium | `technitium/dns-server` |
