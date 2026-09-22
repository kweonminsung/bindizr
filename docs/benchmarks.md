# Benchmarks

Bindizr, paired with each secondary it supports — BIND9, Knot DNS, NSD, and
PowerDNS — measured against PowerDNS Authoritative, Technitium DNS, Knot DNS,
CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and
container limits — the suite lives in
[benchmarks/](https://github.com/kweonminsung/bindizr/blob/main/benchmarks/README.md).
Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each
container capped at 4 CPU / 4 GB.

## No overhead on the query path

![DNS query throughput: CoreDNS 59,916 QPS, Bindizr + BIND9 59,397 against Native BIND9 59,904, Bindizr + NSD 58,114, Bindizr + PowerDNS 56,949 against PowerDNS 56,988, Bindizr + Knot DNS 40,211 against Knot DNS 40,408, Technitium 12,072](assets/benchmarks/b08_query_throughput_light.svg#only-light)
![DNS query throughput: CoreDNS 59,916 QPS, Bindizr + BIND9 59,397 against Native BIND9 59,904, Bindizr + NSD 58,114, Bindizr + PowerDNS 56,949 against PowerDNS 56,988, Bindizr + Knot DNS 40,211 against Knot DNS 40,408, Technitium 12,072](assets/benchmarks/b08_query_throughput_dark.svg#only-dark)

Bindizr never answers a client query — the secondary does — so each pairing
serves what that server serves on its own. `Bindizr + BIND9` serves **59,397
QPS against native BIND9's 59,904** (−0.8%), `Bindizr + PowerDNS` 56,949
against PowerDNS's 56,988 (−0.1%), and `Bindizr + Knot DNS` 40,211 against
Knot's 40,408 (−0.5%), all within run-to-run noise, and Bindizr itself draws
no measurable CPU under that load. NSD has no standalone run in the suite, so
its pairing's 58,114 stands on its own.

## Bulk import

![Bulk import of 10,000 records: Bindizr zone file 112,820 records/sec, Bindizr bulk API 96,925, BIND9 + rndc 91,506, PowerDNS 33,857, Knot DNS 17,644, CoreDNS 10,018, Technitium 8,865](assets/benchmarks/b02_bulk_import_light.svg#only-light)
![Bulk import of 10,000 records: Bindizr zone file 112,820 records/sec, Bindizr bulk API 96,925, BIND9 + rndc 91,506, PowerDNS 33,857, Knot DNS 17,644, CoreDNS 10,018, Technitium 8,865](assets/benchmarks/b02_bulk_import_dark.svg#only-dark)

A 10,000-record zone file imports in **88 ms**; the same records through the
bulk record API take 103 ms. Both paths commit to the database, so the zone
survives a restart and transfers to the secondaries immediately. The number is
the control plane's: this benchmark runs without NOTIFY, and the four pairings
agree within 5%.

## Incremental transfers stay incremental

![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_light.svg#only-light)
![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_dark.svg#only-dark)

A version per SOA serial means an IXFR carries only what changed: **736 B for a
single change in a 100,000-record zone**, where the full zone is 5.5 MB. BIND9,
Knot DNS, and NSD secondaries re-serve that delta byte for byte; PowerDNS,
standalone or as the secondary, answers the same request with the entire zone.
Knot DNS and Technitium standalone track the Bindizr curve.

## Write path

![Median record-create latency from API call to DNS visibility: Technitium 0.6 to 4.9 ms, PowerDNS 2.9 to 7.6 ms, Bindizr + NSD 3.8 to 8.1 ms, Knot DNS 16.7 to 21.2 ms, BIND9 + nsupdate 17.6 to 22.3 ms, Bindizr + Knot DNS 4.0 to 62.8 ms, Bindizr + BIND9 4.3 to 64.7 ms, Bindizr + PowerDNS 4.3 to 1,008 ms](assets/benchmarks/b03_propagation_light.svg#only-light)
![Median record-create latency from API call to DNS visibility: Technitium 0.6 to 4.9 ms, PowerDNS 2.9 to 7.6 ms, Bindizr + NSD 3.8 to 8.1 ms, Knot DNS 16.7 to 21.2 ms, BIND9 + nsupdate 17.6 to 22.3 ms, Bindizr + Knot DNS 4.0 to 62.8 ms, Bindizr + BIND9 4.3 to 64.7 ms, Bindizr + PowerDNS 4.3 to 1,008 ms](assets/benchmarks/b03_propagation_dark.svg#only-dark)

A create is acknowledged in **4.3 ms**; when it answers from DNS depends on the
secondary: **8 ms** after the call with NSD, **65 ms** with BIND9 (p95 75 ms,
p99 79 ms, no timeouts), 63 ms with Knot DNS, and 1.0 s with PowerDNS, which
applies a NOTIFY on its secondary communicator's next pass. Bindizr commits to
the database and propagates by NOTIFY + IXFR, where the integrated servers
answer from their own process as soon as they accept the write.

## Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 397.9 | 362.7 | 345.4 | 13,486.6 | 2.96 ms | 0.00% |
| Bindizr + Knot DNS | 415.6 | 369.6 | 366.7 | 13,603.9 | **2.94 ms** | 0.00% |
| Bindizr + NSD | 413.9 | 372.5 | 356.2 | **13,615.2** | **2.94 ms** | 0.00% |
| Bindizr + PowerDNS | 410.0 | 374.2 | 364.7 | 13,527.0 | 2.99 ms | 0.00% |
| Technitium DNS | **6,853.6** | **4,783.3** | **5,208.8** | 10,401.9 | 3.59 ms | 0.00% |
| Knot DNS | 716.7 | 1,091.6 | 743.9 | 1,147.2 | 38.38 ms | 0.00% |
| BIND9 + nsupdate | 383.0 | 880.3 | 373.0 | 1,147.2 | 38.44 ms | 0.00% |
| PowerDNS Authoritative | 83.4 | 67.1 | 82.1 | 2,883.7 | 4.36 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the
per-record write rate — servers that hold the zone in memory do more per second
here. The rate is the control plane's, so the four pairings agree within
run-to-run noise. These runs use SQLite; PostgreSQL puts creates at 417/sec
against SQLite's 383. Read is a management-plane read: an API `GET` where there
is an API, a `dig` subprocess otherwise, so those p95s carry process-spawn cost.

## Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory (stack) |
| --- | --- | --- | --- | --- | --- |
| SQLite | 382.7 | 13,322.5 | 3.00 ms | 0.91 s (110,220/sec) | 190 MB |
| MySQL | 224.5 | 12,357.6 | 4.68 ms | 2.57 s (39,246/sec) | 917 MB |
| PostgreSQL | 416.5 | 11,756.0 | 4.65 ms | 2.63 s (38,312/sec) | 347 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.
Peak memory is the whole stack (Bindizr + the secondary + the DB server
container) at its highest point, the 100k import; the DB server dominates it —
the MySQL container alone accounts for ~784 MB with its default buffer pool and
`performance_schema` on, against ~215 MB for PostgreSQL. Bindizr's own process
peaks at 24–28 MB there with an external database (85 MB with SQLite, which
runs in-process) and holds 10–12 MB under the CRUD load (44 MB with SQLite).
These are the BIND9 pairing's figures; the other three land within run-to-run
noise on every backend.

??? note "Software under test"

    | Software | Version |
    | --- | --- |
    | BIND9 | `internetsystemsconsortium/bind9:9.21` |
    | Bindizr | built from source |
    | CoreDNS | `coredns/coredns:1.14.7` |
    | Knot DNS | `cznic/knot:3.6` |
    | MySQL | `mysql:26.7` |
    | NSD | Alpine 3.24 package, in an image the suite builds |
    | PostgreSQL | `postgres:18` |
    | PowerDNS | `powerdns/pdns-auth-49:4.9.17` |
    | Technitium | `technitium/dns-server:15.5.0` |
