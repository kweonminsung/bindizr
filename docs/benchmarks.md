# Benchmarks

Bindizr measured against PowerDNS Authoritative, Technitium DNS, Knot DNS,
CoreDNS, and plain BIND9 (nsupdate / rndc) on identical hardware, datasets, and
container limits — the suite lives in
[benchmarks/](https://github.com/kweonminsung/bindizr/blob/main/benchmarks/README.md).
Every figure is the mean of 5 runs on an 8-core AMD Ryzen 7 9800X3D, each
container capped at 4 CPU / 4 GB.

## No overhead on the query path

![DNS query throughput: CoreDNS 62,696 QPS, Bindizr + BIND9 62,448, Native BIND9 61,629, PowerDNS 60,406, Knot DNS 41,289, Technitium 13,139](assets/benchmarks/b08_query_throughput_light.svg#only-light)
![DNS query throughput: CoreDNS 62,696 QPS, Bindizr + BIND9 62,448, Native BIND9 61,629, PowerDNS 60,406, Knot DNS 41,289, Technitium 13,139](assets/benchmarks/b08_query_throughput_dark.svg#only-dark)

Bindizr never answers a client query — the BIND9 secondaries do. `Bindizr +
BIND9` serves **62,448 QPS against native BIND9's 61,629** (−1.3%, within
run-to-run noise), and Bindizr itself draws 0.7% CPU under that load.

## Bulk import

![Bulk import of 10,000 records: Bindizr zone file 132,720 records/sec, BIND9 + rndc 102,641, Bindizr bulk API 93,364, PowerDNS 36,443, Knot DNS 18,514, CoreDNS 10,374, Technitium 9,244](assets/benchmarks/b02_bulk_import_light.svg#only-light)
![Bulk import of 10,000 records: Bindizr zone file 132,720 records/sec, BIND9 + rndc 102,641, Bindizr bulk API 93,364, PowerDNS 36,443, Knot DNS 18,514, CoreDNS 10,374, Technitium 9,244](assets/benchmarks/b02_bulk_import_dark.svg#only-dark)

A 10,000-record zone file imports in **76 ms**; the same records through the
bulk record API take 107 ms. Both paths commit to the database, so the zone
survives a restart and transfers to the secondaries immediately.

## Incremental transfers stay incremental

![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_light.svg#only-light)
![IXFR transfer size in a 100,000-record zone: Bindizr moves 736 B for 1 change up to 558 KB for 10,000 changes, while PowerDNS moves about 5.5 MB regardless of the change count](assets/benchmarks/b05_ixfr_size_dark.svg#only-dark)

A snapshot per SOA serial means an IXFR carries only what changed: **736 B for a
single change in a 100,000-record zone**, where the full zone is 5.5 MB.
PowerDNS answers the same request with the entire zone; Knot DNS and Technitium
track the Bindizr curve.

## Write path

![Median record-create latency from API call to DNS visibility: Technitium 0.6 to 4.6 ms, PowerDNS 2.8 to 7.3 ms, Knot DNS 16.2 to 20.4 ms, BIND9 + nsupdate 17.2 to 21.5 ms, Bindizr + BIND9 6.4 to 65.7 ms](assets/benchmarks/b03_propagation_light.svg#only-light)
![Median record-create latency from API call to DNS visibility: Technitium 0.6 to 4.6 ms, PowerDNS 2.8 to 7.3 ms, Knot DNS 16.2 to 20.4 ms, BIND9 + nsupdate 17.2 to 21.5 ms, Bindizr + BIND9 6.4 to 65.7 ms](assets/benchmarks/b03_propagation_dark.svg#only-dark)

A create is acknowledged in **6.4 ms** and answers from the secondaries **65.7
ms** after the call (p95 83 ms, no timeouts). Bindizr commits to the database
and propagates by NOTIFY + IXFR, where the integrated servers answer from their
own process as soon as they accept the write.

## Record CRUD throughput

| System | Create TPS | Update TPS | Delete TPS | Read TPS | Read p95 | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| Bindizr + BIND9 | 198.1 | 197.1 | 186.8 | **13,916.9** | **2.82 ms** | 0.00% |
| Technitium DNS | **8,992.2** | **8,182.1** | **9,123.3** | 10,594.2 | 3.51 ms | 0.00% |
| Knot DNS | 759.2 | 1,116.3 | 735.1 | 1,203.1 | 36.73 ms | 0.00% |
| BIND9 + nsupdate | 412.8 | 948.2 | 411.4 | 1,199.7 | 36.92 ms | 0.00% |
| PowerDNS Authoritative | 87.4 | 72.1 | 83.9 | 2,962.0 | 4.27 ms | 0.00% |

Each write is a durable database commit plus a zone-serial bump, which sets the
per-record write rate — servers that hold the zone in memory do more per second
here. These runs use SQLite; PostgreSQL raises creates from 199 to 571/sec. Read
is a management-plane read: an API `GET` where there is an API, a `dig`
subprocess otherwise, so those p95s carry process-spawn cost.

## Database backends

| Backend | Create TPS | Read TPS | Read p95 | 100k bulk import | Peak memory |
| --- | --- | --- | --- | --- | --- |
| SQLite | 198.6 | 14,236.1 | 2.78 ms | 0.96 s (104,391/sec) | 120 MB |
| MySQL | 262.0 | 12,766.3 | 4.35 ms | 2.04 s (48,994/sec) | 879 MB |
| PostgreSQL | 571.3 | 12,432.4 | 4.23 ms | 1.98 s (50,647/sec) | 325 MB |

Bulk import stays near-linear from 10k to 100k records on all three backends.

??? note "Software under test"

    | Software | Version |
    | --- | --- |
    | BIND9 | `internetsystemsconsortium/bind9:9.21` |
    | Bindizr | built from source |
    | CoreDNS | `coredns/coredns:1.14.6` |
    | Knot DNS | `cznic/knot:3.5` |
    | MySQL | `mysql:9.7` |
    | PostgreSQL | `postgres:18` |
    | PowerDNS | `powerdns/pdns-auth-49` |
    | Technitium | `technitium/dns-server` |
