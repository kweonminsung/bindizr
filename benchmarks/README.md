# Bindizr Benchmark Suite

Reproducible, apples-to-apples benchmarks comparing **Bindizr**, paired with
each secondary it supports (BIND9, Knot DNS, NSD, PowerDNS), against other DNS
management approaches on identical hardware, datasets, and network conditions. Everything runs in Docker Compose and is driven by a single command.

```bash
cd benchmarks
pip install -r requirements.txt      # aiohttp, PyYAML, matplotlib (use --user/--break-system-packages if needed)
./benchmark.sh --ci                  # quick run (small sizes)
./benchmark.sh                       # full run
BENCH_ARM=true ./benchmark.sh        # on an ARM host (e.g. Apple Silicon)
```

`BENCH_ARM=true` layers each system's `compose.arm.yml`, building BIND from
Debian: the ISC image is amd64-only and segfaults under emulation, taking every
`bind9`-based system with it. That is BIND 9.20 against ISC's 9.21, so ARM
numbers are internally consistent but not comparable with amd64 ones.

Each run writes to its own `results_<YYYYmmdd_HHMMSS>/` directory:
`performance.md` (paste-into-README tables), `performance.csv`,
`performance.json`, and `graphs/*.png`.

## Systems under test

| Key | Label | Kind |
| --- | --- | --- |
| `bindizr` | Bindizr + BIND9 | control plane (writes DB, propagates via AXFR/IXFR; **outside the query data plane**) |
| `bindizr_knot` | Bindizr + Knot DNS | same control plane, Knot DNS as the secondary |
| `bindizr_nsd` | Bindizr + NSD | same control plane, NSD as the secondary |
| `bindizr_pdns` | Bindizr + PowerDNS | same control plane, PowerDNS as the secondary |
| `powerdns` | PowerDNS Authoritative | integrated server + REST API (gsqlite3) |
| `technitium` | Technitium DNS | integrated server + HTTP API |
| `bind9_nsupdate` | BIND9 + nsupdate | RFC 2136 dynamic updates |
| `bind9_rndc` | BIND9 + rndc | zone-file edits + `rndc reload` |
| `bind9_native` | Native BIND9 | plain authoritative primary (query baseline) |
| `knot` | Knot DNS | RFC 2136 dynamic updates + journal-backed IXFR |
| `coredns` | CoreDNS | zone file + `file` plugin mtime-poll reload (no management API) |

> **The four Bindizr pairings.** `bindizr*` share one control plane and differ
> only in which server answers queries. B7 turns NOTIFY off and the four agree
> there (within ~2%), but writes elsewhere do not: each one sends a NOTIFY the
> secondary answers with a transfer, so B1's create throughput varies with which
> secondary absorbs that. Reads, which notify nobody, agree throughout.
> `knot` and `powerdns` without the prefix are a different comparison — those
> run standalone with their own write plane.

> **Two NSD defaults are overridden** so B3 and B5 measure the transfer rather
> than NSD's scheduling, since BIND and Knot have no equivalent. `xfrd-reload-timeout: 0`
> applies a transfer as it lands (default 1s: **1050ms vs 6.7ms** p50 visibility,
> at **1.7% vs 16.5%** CPU), and `store-ixfr: yes` keeps received deltas so an
> IXFR is answered with one (**700 bytes vs 55KB** for a single-record change).
> With both set NSD re-serves byte-identical deltas to Knot's.

> **PowerDNS propagation** is roughly 1s p50 on B3, because PowerDNS acts on a
> NOTIFY when its secondary communicator next runs. There is no setting to
> raise it, so it is reported as measured.

> **CoreDNS scope.** CoreDNS has no management API and no RFC 2136 dynamic
> update — a write means rewriting the zone file and waiting for the `file`
> plugin's mtime poll (`reload 1s`; there is no `rndc reload` equivalent). It
> therefore runs only where that is a fair measurement: **bulk** (one reload for
> the whole set), **AXFR**, **query**, and **resources**. Its bulk number
> includes that reload latency, so read it as *write-visibility* cost, not
> record throughput. It is excluded from per-record CRUD (B1) and propagation
> (B3), where the poll interval rather than the server would dominate, and from
> IXFR (B5) — CoreDNS keeps no journal and answers IXFR with a full transfer.

## Benchmarks

| # | Key | What it measures | Systems |
| --- | --- | --- | --- |
| 1 | `b01_crud_tps` | Record Create/Read/Update/Delete TPS, p50/p95/p99, error rate | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, bind9_nsupdate, knot |
| 2 | `b02_bulk_import` | Import 1K–1M records: time, records/sec, peak mem/CPU | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, bind9_rndc, knot, coredns* |
| 3 | `b03_propagation` | Create → API done → **DNS-visible** latency (p50/p95/p99) | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, bind9_nsupdate, knot |
| 4 | `b04_axfr` | Full zone transfer time, size, records/sec | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, knot, coredns |
| 5 | `b05_ixfr` | Incremental transfer size/time for 1–1000 changes | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, knot |
| 6 | `b06_large_zone` | Zone create/populate/export/delete + mem/CPU by size | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns |
| 7 | `b07_database` | Bindizr CRUD **and bulk import (10k/100k)** across SQLite / MySQL / PostgreSQL | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns |
| 8 | `b08_query_perf` | DNS **QPS** + latency; proves zero query-path overhead | native, bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, knot, coredns |
| 9 | `b09_resource_usage` | CPU/mem/net under steady query load | bindizr, bindizr_knot, bindizr_nsd, bindizr_pdns, powerdns, technitium, knot, coredns |

<sub>\* CoreDNS's bulk number includes its zone-file reload poll — see the CoreDNS scope note above.</sub>

### The Benchmark 8 claim

Bindizr sits **outside the DNS data plane**: clients query the secondary, not
Bindizr. Benchmark 8 verifies that each pairing's QPS matches the same server
run standalone — `Bindizr + BIND9` against `Native BIND9`, `Bindizr + Knot DNS`
against `Knot DNS`, `Bindizr + PowerDNS` against `PowerDNS Authoritative` —
i.e. **Bindizr introduces no measurable DNS query overhead**. NSD has no
standalone run, so its pairing is reported without a comparison.

## Methodology & fairness

- **Common interface.** Every system implements the same adapter
  ([`adapters/base.py`](adapters/base.py)); a runner issues one identical
  workload against all of them. Architectural differences (replacing every
  record at a name and type at once vs. addressing records by id,
  dynamic-update vs REST) are hidden in the adapter.
- **Cross-cutting metric.** Because architectures differ, the honest comparison
  for write paths is *end-to-end* (Benchmark 3: create → DNS-visible). API-level
  TPS (Benchmark 1) is reported alongside, not in place of it.
- **Bounded resources.** Every SUT container runs under identical CPU/memory
  caps (default **4 CPU / 4 GB**, via `deploy.resources.limits`) so results are
  reproducible across machines and no system can burst to the whole host.
  Override with `BENCH_CPU_LIMIT` / `BENCH_MEM_LIMIT`. The load generator runs on
  the host (unlimited), as is standard — the *server* is what's constrained.
- **notify_after_update split.** Bindizr's write path can either (a) just persist
  to the DB — the adapter registers no secondary, so a write notifies nobody —
  or (b) additionally push NOTIFY+XFR to the registered secondary synchronously.
  Management-plane benchmarks (B1 CRUD, B2 bulk, B7 database) run with
  `notify_after_update=false` to isolate raw write throughput; propagation /
  AXFR / IXFR / query / resource benchmarks run with it **on** because they
  require the secondary to receive updates. (TTL is fixed at 3600 and not varied
  — the query benchmarks hit authoritative servers directly, so resolver-cache
  TTL effects don't apply.)
- **Repeatable & averaged.** A full run repeats every measurement **5 times**
  (`repeats` in `config/settings.yaml`; CI uses `repeats_ci: 1`, override with
  `BENCH_REPEATS=N`). The report averages numeric metrics per system/backend,
  reports the **sample standard deviation** as `mean ± std` on headline metrics,
  and shows a `runs` column. Each full run starts from a clean `raw/` under its
  own results directory, and
  every system is `down -v`'d before setup, so runs never accumulate
  stale/duplicate rows.
- **Reproducible.** A fixed seed (`config/settings.yaml`) generates the same
  dataset every run; workload order is deterministic.
- **Isolated.** Each system is set up, exercised, and torn down on its own; only
  one runs at a time so the host is never contended.
- **Environment recorded.** CPU/mem/OS/Docker, per-container limits, repeats, and
  all image versions are written into every report.

## Batch-size guidance

Bulk/import clients choose how many records to send per request
(`BENCH_BINDIZR_BULK_CHUNK` / `BENCH_BINDIZR_IMPORT_CHUNK`); Bindizr applies
each request as one transaction + serial bump + NOTIFY. Per-record DB-write cost
is flat, so a larger batch only amortizes that per-request fixed cost
(transaction, serial bump, snapshot, JSON decode) — gains flatten past ~5,000
records/request while peak memory keeps growing, making **~5,000** the
recommended default. On MySQL the dominant per-request cost is the
existing-record `SELECT … FOR UPDATE` lookup rather than the insert, so batch
size matters far less there.

## Layout

```
benchmarks/
  benchmark.sh              # entrypoint (preflight, run, teardown)
  orchestrator.py           # drives benchmarks × systems, writes the report
  config/settings.yaml      # sizes, workload knobs, seed, system/benchmark matrix
  datasets/gen_dataset.py   # deterministic record generator
  adapters/                 # base interface + registry
  systems/<key>/            # compose.yml + config + adapter.py per system
  runners/bNN_*.py          # one module per benchmark
  lib/                      # metrics, loadgen, dnsquery, resources, report, env
  results_<timestamp>/      # generated artifacts (md/csv/json/graphs), one dir per run
```

## Configuration & overrides

Defaults live in [`config/settings.yaml`](config/settings.yaml). Handy env
overrides (used by CI and quick runs):

| Env | Effect |
| --- | --- |
| `BENCH_CI=1` | use small CI sizes |
| `BENCH_RESULTS_DIR=results_20260710_233856` | reuse an existing results directory instead of creating one; pass it when re-running a subset (`-b ...`) so the report is rebuilt from the full raw set |
| `BENCH_SIZES=1000,10000` | override bulk/AXFR sizes |
| `BENCH_SEED=1337` | dataset seed |
| `BENCH_CRUD_DURATION` / `BENCH_CRUD_CONCURRENCY` / `BENCH_CRUD_PREPOP` | CRUD window/load |
| `BENCH_QUERY_DURATION` / `BENCH_QUERY_ZONE_SIZE` | query load |
| `BENCH_PROP_SAMPLES` | propagation samples |
| `BENCH_CPU_LIMIT` / `BENCH_MEM_LIMIT` | per-SUT-container caps (default `4` / `4g`) |
| `BENCH_REPEATS` | repeat each measurement N times and average (default `5`, CI `1`) |
| `BENCH_DB_BULK_SIZES=10000,100000` | per-backend bulk-import sizes (Benchmark 7) |
| `BENCH_BINDIZR_LOG_LEVEL=debug` | surface Bindizr's per-stage timing lines (`event=record_bulk_create_timing` / `event=zone_import_timing`) in the container logs |
| `BENCH_BINDIZR_BULK_CHUNK` / `BENCH_BINDIZR_IMPORT_CHUNK` | records per JSON-bulk / zone-import request (default `2000` / `5000`); set equal to compare the two paths apples-to-apples, since each chunk is one transaction + serial bump + NOTIFY |

The **1,000,000-record** size is heavy (time + disk) and excluded from CI; run it
explicitly with `BENCH_SIZES=1000000`.

To read the per-stage breakdown after a run, grep the Bindizr container logs (with
`BENCH_BINDIZR_LOG_LEVEL=debug`) for `event=record_bulk_create_timing` /
`event=zone_import_timing`; each line reports `*_ms` for every stage plus `total_ms`.

## Requirements

- Docker + Docker Compose v2
- Host tools: `dig`, `nsupdate` (Debian/Ubuntu: `dnsutils` / `bind9-dnsutils`)
- Python 3.10+ with `aiohttp`, `PyYAML`, `matplotlib`
