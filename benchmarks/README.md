# Bindizr Benchmark Suite

Reproducible, apples-to-apples benchmarks comparing **Bindizr + BIND9** against
other DNS management approaches on identical hardware, datasets, and network
conditions. Everything runs in Docker Compose and is driven by a single command.

```bash
cd benchmarks
pip install -r requirements.txt      # aiohttp, PyYAML, matplotlib (use --user/--break-system-packages if needed)
./benchmark.sh --ci                  # quick run (small sizes)
./benchmark.sh                       # full run
```

Results land in [`results/`](results/): `performance.md` (paste-into-README
tables), `performance.csv`, `performance.json`, and `graphs/*.png`.

## Systems under test

| Key | Label | Kind |
| --- | --- | --- |
| `bindizr` | Bindizr + BIND9 | control plane (writes DB, propagates via AXFR/IXFR; **outside the query data plane**) |
| `powerdns` | PowerDNS Authoritative | integrated server + REST API (gsqlite3) |
| `technitium` | Technitium DNS | integrated server + HTTP API |
| `bind9_nsupdate` | BIND9 + nsupdate | RFC 2136 dynamic updates |
| `bind9_rndc` | BIND9 + rndc | zone-file edits + `rndc reload` |
| `bind9_native` | Native BIND9 | plain authoritative primary (query baseline) |

> Multi-master scalability (original Benchmark 6) is **omitted** — it needs
> Kubernetes/clustering that this Docker-only harness does not cover.

## Benchmarks

| # | Key | What it measures | Systems |
| --- | --- | --- | --- |
| 1 | `b01_crud_tps` | Record Create/Read/Update/Delete TPS, p50/p95/p99, error rate | bindizr, powerdns, technitium, bind9_nsupdate |
| 2 | `b02_bulk_import` | Import 1K–1M records: time, records/sec, peak mem/CPU | bindizr, powerdns, technitium, bind9_rndc |
| 3 | `b03_propagation` | Create → API done → **DNS-visible** latency (p50/p95/p99) | bindizr, powerdns, technitium, bind9_nsupdate |
| 4 | `b04_axfr` | Full zone transfer time, size, records/sec | bindizr, powerdns, technitium |
| 5 | `b05_ixfr` | Incremental transfer size/time for 1–1000 changes | bindizr, powerdns, technitium |
| 6 | `b06_large_zone` | Zone create/populate/export/delete + mem/CPU by size | bindizr |
| 7 | `b07_database` | Bindizr CRUD across SQLite / MySQL / PostgreSQL | bindizr |
| 8 | `b08_query_perf` | DNS **QPS** + latency; proves zero query-path overhead | native, bindizr, powerdns, technitium |
| 9 | `b09_resource_usage` | CPU/mem/net under steady query load | bindizr, powerdns, technitium |

> The original multi-master scalability benchmark (Kubernetes/clustering) is
> omitted, so benchmarks are numbered 1–9 with no gap.

### The Benchmark 8 claim

Bindizr sits **outside the DNS data plane**: clients query the BIND9 secondaries,
not Bindizr. Benchmark 8 verifies that `Bindizr + BIND9` QPS matches `Native
BIND9` — i.e. **Bindizr introduces no measurable DNS query overhead**.

## Methodology & fairness

- **Common interface.** Every system implements the same adapter
  ([`adapters/base.py`](adapters/base.py)); a runner issues one identical
  workload against all of them. Architectural differences (RRset vs record-id,
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
  to the DB, or (b) additionally push NOTIFY+XFR to secondaries synchronously.
  Management-plane benchmarks (B1 CRUD, B2 bulk, B7 database) run with
  `notify_after_update=false` to isolate raw write throughput; propagation /
  AXFR / IXFR / query / resource benchmarks run with it **on** because they
  require the secondary to receive updates. (TTL is fixed at 3600 and not varied
  — the query benchmarks hit authoritative servers directly, so resolver-cache
  TTL effects don't apply.)
- **Repeatable & averaged.** Set `BENCH_REPEATS=N` to run every measurement N
  times; the report averages numeric metrics per system/backend and shows a
  `runs` column. Each full run starts from a clean `results/raw`, and every
  system is `down -v`'d before setup, so runs never accumulate stale/duplicate
  rows.
- **Reproducible.** A fixed seed (`config/settings.yaml`) generates the same
  dataset every run; workload order is deterministic.
- **Isolated.** Each system is set up, exercised, and torn down on its own; only
  one runs at a time so the host is never contended.
- **Environment recorded.** CPU/mem/OS/Docker, per-container limits, repeats, and
  all image versions are written into every report.

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
  results/                  # generated artifacts (md/csv/json/graphs)
```

## Configuration & overrides

Defaults live in [`config/settings.yaml`](config/settings.yaml). Handy env
overrides (used by CI and quick runs):

| Env | Effect |
| --- | --- |
| `BENCH_CI=1` | use small CI sizes |
| `BENCH_SIZES=1000,10000` | override bulk/AXFR sizes |
| `BENCH_SEED=1337` | dataset seed |
| `BENCH_CRUD_DURATION` / `BENCH_CRUD_CONCURRENCY` / `BENCH_CRUD_PREPOP` | CRUD window/load |
| `BENCH_QUERY_DURATION` / `BENCH_QUERY_ZONE_SIZE` | query load |
| `BENCH_PROP_SAMPLES` | propagation samples |
| `BENCH_CPU_LIMIT` / `BENCH_MEM_LIMIT` | per-SUT-container caps (default `4` / `4g`) |
| `BENCH_REPEATS` | repeat each measurement N times and average (default 1) |

The **1,000,000-record** size is heavy (time + disk) and excluded from CI; run it
explicitly with `BENCH_SIZES=1000000`.

## Requirements

- Docker + Docker Compose v2
- Host tools: `dig`, `nsupdate` (Debian/Ubuntu: `dnsutils` / `bind9-dnsutils`)
- Python 3.10+ with `aiohttp`, `PyYAML`, `matplotlib`

## CI

[`.github-workflow-benchmark.yml`](.github-workflow-benchmark.yml) runs a small
comparison on manual dispatch and uploads `results/` as an artifact. Copy it to
`.github/workflows/benchmark.yml` to enable.
