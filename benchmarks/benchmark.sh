#!/usr/bin/env bash
# Bindizr Benchmark Suite — single entrypoint.
#
# Runs the full comparison (or a subset), collects results, and writes the
# report under results_<timestamp>/ (performance.md/csv/json + graphs/). All
# state is torn down on exit.
#
# Usage:
#   ./benchmark.sh                       # all benchmarks, all enabled systems
#   ./benchmark.sh -b b01_crud_tps       # one benchmark
#   ./benchmark.sh -b b08_query_perf -s bindizr,bind9_native
#   ./benchmark.sh --ci                  # small sizes for CI
#   ./benchmark.sh --list                # list benchmarks
#
# Environment overrides (see lib/settings.py): BENCH_CI, BENCH_SIZES, BENCH_SEED,
#   BENCH_CRUD_DURATION, BENCH_QUERY_ZONE_SIZE, BENCH_PROP_SAMPLES, ...
set -euo pipefail

cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
ARGS=()
SYSTEMS=""
BENCHES=""

usage() { sed -n '2,20p' "$0"; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--benchmarks) BENCHES="$2"; shift 2 ;;
    -s|--systems)    SYSTEMS="$2"; shift 2 ;;
    --ci)            export BENCH_CI=1; shift ;;
    --list)          "$PYTHON" orchestrator.py --list; exit 0 ;;
    -h|--help)       usage ;;
    *)               echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- preflight ---------------------------------------------------------------
command -v docker >/dev/null || { echo "ERROR: docker not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not reachable" >&2; exit 1; }
command -v dig >/dev/null || { echo "ERROR: dig (dnsutils) not found" >&2; exit 1; }
command -v nsupdate >/dev/null || echo "WARN: nsupdate not found; BIND9+nsupdate benchmark will be skipped"
"$PYTHON" -c "import aiohttp, yaml, matplotlib" 2>/dev/null || {
  echo "ERROR: missing Python deps. Run: pip install -r requirements.txt" >&2; exit 1; }

# --- cleanup on exit ---------------------------------------------------------
cleanup() {
  echo ">>> tearing down any leftover benchmark stacks..."
  for p in $(docker compose ls -q 2>/dev/null | grep '^bench-' || true); do
    docker compose -p "$p" down -v --remove-orphans >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM

# --- run ---------------------------------------------------------------------
[[ -n "$BENCHES" ]] && ARGS+=(-b ${BENCHES//,/ })
[[ -n "$SYSTEMS" ]] && ARGS+=(-s ${SYSTEMS//,/ })

echo ">>> starting benchmark run"
"$PYTHON" orchestrator.py "${ARGS[@]}"
echo ">>> done. Results written under results_<timestamp>/ (exact path printed above)."
