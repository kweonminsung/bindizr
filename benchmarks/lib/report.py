"""Result persistence + final report generation (md / csv / json / png).

Each runner appends a structured result via `write_result`. `write_report` then
aggregates everything under results_<timestamp>/ into performance.{json,csv,md}
and renders graphs/*.png. Graph rendering is best-effort (skipped if matplotlib
absent).
"""
from __future__ import annotations

import csv
import json
from statistics import stdev
from typing import Any

from .settings import GRAPHS_DIR, RESULTS_DIR

RAW_DIR = RESULTS_DIR / "raw"


def write_result(benchmark: str, result: dict[str, Any]) -> None:
    """Append one benchmark result to its raw JSON file."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out = RAW_DIR / f"{benchmark}.json"
    payload: dict[str, Any] = {"benchmark": benchmark, "results": []}
    if out.exists():
        payload = json.loads(out.read_text())
    payload["results"].append(result)
    out.write_text(json.dumps(payload, indent=2))


def _load_all() -> dict[str, dict]:
    """Load all saved raw benchmark result files."""
    data: dict[str, dict] = {}
    if RAW_DIR.exists():
        for f in sorted(RAW_DIR.glob("*.json")):
            payload = json.loads(f.read_text())
            data[payload["benchmark"]] = payload
    return data


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Render headers and rows as a Markdown table."""
    line = "| " + " | ".join(headers) + " |\n"
    line += "| " + " | ".join("---" for _ in headers) + " |\n"
    for r in rows:
        line += "| " + " | ".join(str(c) for c in r) + " |\n"
    return line


def write_report(env: dict, cfg: dict) -> None:
    """Write the combined JSON, CSV, Markdown, and graph reports."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    data = _load_all()

    full = {"environment": env, "config_seed": cfg.get("seed"), "benchmarks": data}
    (RESULTS_DIR / "performance.json").write_text(json.dumps(full, indent=2))

    csv_rows: list[dict] = []
    for name, payload in data.items():
        for r in payload["results"]:
            row = {"benchmark": name}
            row.update({k: v for k, v in r.items() if not isinstance(v, (dict, list))})
            csv_rows.append(row)
    if csv_rows:
        keys: list[str] = []
        for r in csv_rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        with open(RESULTS_DIR / "performance.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(csv_rows)

    (RESULTS_DIR / "performance.md").write_text(_render_markdown(env, data))
    _write_graphs(data)


# Fields that identify a distinct measurement (not metrics to average over).
# `status` is a dimension so a FAILED row is never merged into a successful one
# sharing the other fields.
DIMENSION_FIELDS = ("system", "backend", "size", "changes", "status")


def _aggregate(rows: list[dict]) -> list[dict]:
    """Collapse repeated runs: group by dimension fields, average numeric metrics
    into `<metric>` plus a `<metric>_std`, and count them in `runs`.

    A metric is only averaged when every run in the group reported it as a
    number; otherwise the first run's value carries through, since a mean over a
    subset would silently describe fewer runs than the `runs` count claims.
    """
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(str(r.get(f)) for f in DIMENSION_FIELDS), []).append(r)

    out = []
    for grp in groups.values():
        base = grp[0]
        agg: dict = {}
        for k in base:
            vals = [g.get(k) for g in grp]
            numeric = [v for v in vals
                       if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if k not in DIMENSION_FIELDS and numeric and len(numeric) == len(vals):
                agg[k] = round(sum(numeric) / len(numeric), 3)
                agg[f"{k}_std"] = round(stdev(numeric), 3) if len(numeric) > 1 else 0.0
            else:
                agg[k] = base.get(k)
        if len(grp) > 1:
            agg["runs"] = len(grp)
        out.append(agg)
    return out


def _pm(row: dict, key: str, prec: int = 1, default: Any = "-") -> str:
    """Render a metric as `mean ± std` (std omitted when 0 / single run)."""
    mean = row.get(key)
    if not isinstance(mean, (int, float)) or isinstance(mean, bool):
        return default
    std = row.get(f"{key}_std", 0) or 0
    if std:
        return f"{mean:.{prec}f} ± {std:.{prec}f}"
    return f"{mean:.{prec}f}"


def _bulk_linearity_note(rows: list[dict]) -> str:
    """Per-series 10k→100k scaling: import time should grow ~10x for 10x records."""
    by_sys: dict[str, dict[int, float]] = {}
    for r in rows:
        secs = r.get("import_secs")
        if isinstance(r.get("size"), int) and isinstance(secs, (int, float)):
            by_sys.setdefault(r["system"], {})[r["size"]] = secs
    lines = []
    for system, bysize in by_sys.items():
        if 10000 in bysize and 100000 in bysize and bysize[10000]:
            ratio = bysize[100000] / bysize[10000]
            verdict = "near-linear" if 8.0 <= ratio <= 12.0 else "super-linear" \
                if ratio > 12.0 else "sub-linear"
            lines.append(
                f"- **{system}:** 10k → {bysize[10000]:.2f}s, "
                f"100k → {bysize[100000]:.2f}s ({ratio:.1f}× for 10× records → {verdict})")
    if not lines:
        return ""
    return ("\n> **10k → 100k scaling** (ideal 10.0× — confirms bulk import stays "
            "linear at scale):\n" + "\n".join(lines) + "\n")


# Gap below which a QPS difference is treated as run-to-run noise, not overhead.
QUERY_NOISE_TOLERANCE_PCT = 5.0


#: Each Bindizr pairing is read against the same server run standalone, since
#: that server, not Bindizr, answers the pairing's queries. NSD has no
#: standalone run, so its pairing carries no comparison.
QUERY_BASELINES = {
    "Bindizr + BIND9": "Native BIND9",
    "Bindizr + Knot DNS": "Knot DNS",
    "Bindizr + PowerDNS": "PowerDNS Authoritative",
}


def _b08_query_delta(row: dict, comparable: dict[str, dict]) -> str:
    """Render a query row's QPS relative to its standalone server: the signed
    percentage for a pairing whose server ran, `baseline` for a server a
    pairing is read against, `-` otherwise or where either side lacks a
    positive QPS."""
    standalone = comparable.get(QUERY_BASELINES.get(row["system"], ""))
    if standalone and row["system"] in comparable:
        return f'{(row["qps"] / standalone["qps"] - 1) * 100:+.1f}%'
    if row["system"] in QUERY_BASELINES.values():
        return "baseline"
    return "-"


def _b08_conclusion(comparable: dict[str, dict]) -> str:
    """The no-overhead claim is a measured outcome, not a premise: state it per
    pairing, only where both sides produced a positive QPS and the gap is
    inside the tolerance."""
    within: list[str] = []
    outside: list[str] = []
    for pairing, standalone in QUERY_BASELINES.items():
        p, s = comparable.get(pairing), comparable.get(standalone)
        if not p or not s:
            continue
        delta = (p["qps"] / s["qps"] - 1) * 100
        entry = f"`{pairing}` vs `{standalone}` ({delta:+.1f}%)"
        (within if abs(delta) <= QUERY_NOISE_TOLERANCE_PCT else outside).append(entry)
    if not within and not outside:
        return ("\n> ⚠️ No-overhead conclusion unavailable: this run has no Bindizr "
                "pairing and standalone run of the same server to compare.\n")

    out = ""
    if within:
        out += ("\n> **Bindizr introduces no measurable DNS query overhead because it "
                "is outside the DNS data plane.** Queries are served by the secondary, "
                "not by Bindizr, so each pairing tracks that server run standalone: "
                + ", ".join(within)
                + f" — within the ±{QUERY_NOISE_TOLERANCE_PCT:.0f}% run-to-run tolerance.\n")
    if outside:
        out += (f"\n> ⚠️ Outside the ±{QUERY_NOISE_TOLERANCE_PCT:.0f}% noise tolerance, "
                "so this run does not support the no-overhead conclusion there: "
                + ", ".join(outside) + ".\n")
    return out


def _render_b07(rows: list[dict]) -> str:
    """Benchmark 7 emits two row shapes: CRUD-lite (create/read TPS) and bulk
    import (import_secs per size). Render them as two separate tables."""
    crud = [r for r in rows if "create_tps" in r]
    bulk = [r for r in rows if "import_secs" in r]
    failed = [r for r in rows if r.get("status") == "FAILED"]
    out = ["\n## Benchmark 7 — Database Performance\n"]

    if crud:
        out.append("\n### 7a — CRUD throughput by backend\n")
        crud = sorted(crud, key=lambda r: (r.get("system", ""),
                                           r.get("backend", "")))
        crud_rows = [[
            r.get("system", "-"),
            r.get("backend", "-"), _pm(r, "create_tps"), _pm(r, "read_tps"),
            _pm(r, "create_p95_ms", 2), _pm(r, "read_p95_ms", 2),
            f'{r.get("error_rate", 0) * 100:.2f}%', r.get("peak_mem_mb", "-"),
            r.get("bindizr_peak_mem_mb", "-"), r.get("db_peak_mem_mb", "-"),
            r.get("runs", 1),
        ] for r in crud]
        out.append(_md_table(
            ["Pairing", "Backend", "Create TPS", "Read TPS", "Create p95 (ms)",
             "Read p95 (ms)", "Error Rate", "Peak mem (MB)",
             "Bindizr mem (MB)", "DB mem (MB)", "Runs"], crud_rows))
        out.append("\n> Peak mem is the highest per-tick stack total (Bindizr "
                   "+ BIND9 + DB server, per `docker stats`). The split "
                   "columns are each container's own peak, taken at possibly "
                   "different ticks and excluding BIND9, so they need not sum "
                   "to it. sqlite runs in-process, so its DB share is 0.\n")

    if bulk:
        out.append("\n### 7b — Bulk import by backend\n")
        bulk = sorted(bulk, key=lambda r: (r.get("system", ""),
                                           r.get("backend", ""),
                                           r.get("size", 0)))
        bulk_rows = [[
            r.get("system", "-"), r.get("backend", "-"), r.get("size", "-"),
            _pm(r, "import_secs", 3), _pm(r, "records_per_sec"),
            r.get("import_errors", "-"), r.get("peak_mem_mb", "-"),
            r.get("bindizr_peak_mem_mb", "-"), r.get("db_peak_mem_mb", "-"),
            r.get("runs", 1),
        ] for r in bulk]
        out.append(_md_table(
            ["Pairing", "Backend", "Records", "Import (s)", "Records/sec", "Errors",
             "Peak mem (MB)", "Bindizr mem (MB)", "DB mem (MB)", "Runs"],
            bulk_rows))
        # One series per pairing and backend, so the note keys on both.
        out.append(_bulk_linearity_note(
            [{**r, "system": f'{r.get("system", "-")} / {r.get("backend", "-")}'}
             for r in bulk]))

    if failed:
        out.append("\n> ⚠️ Failed backends: " +
                   ", ".join(f'{r.get("system", "-")} / {r.get("backend")} '
                             f'({r.get("error", "?")})'
                             for r in failed) + "\n")
    return "".join(out)


def _rows(data: dict, key: str) -> list[dict]:
    """Return aggregated rows for one benchmark when results exist."""
    return _aggregate(data[key]["results"]) if key in data else []


def _union_headers(results: list[dict]) -> list[str]:
    """Collect columns in first-seen order, including failure-only status/error keys."""
    headers: list[str] = []
    for r in results:
        for h in r:
            if not h.endswith("_std") and h not in headers:
                headers.append(h)
    return headers


def _render_markdown(env: dict, data: dict) -> str:
    """Render the environment and benchmark results as a Markdown report."""
    hw = env["hardware"]
    out = ["# Bindizr Benchmark Results\n"]
    out.append("## Test Environment\n")
    out.append(_md_table(
        ["Component", "Value"],
        [
            ["CPU", f"{hw['cpu']} ({hw['cpu_cores']} cores)"],
            ["Memory", f"{hw['memory_gb']} GB"],
            ["Storage (free)", f"{hw['storage_free_gb']} GB"],
            ["OS", env["os"]["platform"]],
            ["Docker", env["docker"]["version"]],
            ["Per-container limit", f"{env.get('limits', {}).get('cpus', '?')} CPU / "
                                    f"{env.get('limits', {}).get('memory', '?')}"],
            ["Repeats (averaged)", env.get("config", {}).get("repeats", 1)],
        ],
    ))
    out.append("\n### Software Versions\n")
    out.append(_md_table(["Software", "Version"],
                         [[k, v] for k, v in env["software"].items()]))

    if "b01_crud_tps" in data:
        out.append("\n## Benchmark 1 — Record CRUD TPS\n")
        rows = []
        for r in _rows(data, "b01_crud_tps"):
            rows.append([
                r["system"], _pm(r, "create_tps"), _pm(r, "update_tps"),
                _pm(r, "delete_tps"), _pm(r, "read_tps"),
                _pm(r, "read_p95_ms", 2), f'{r.get("error_rate", 0) * 100:.2f}%',
                r.get("runs", 1),
            ])
        out.append(_md_table(
            ["Product", "Create TPS", "Update TPS", "Delete TPS", "Read TPS",
             "Read p95 (ms)", "Error Rate", "Runs"], rows))

    # Curated table: mean ± std on time / throughput.
    if "b02_bulk_import" in data:
        results = sorted(_rows(data, "b02_bulk_import"),
                         key=lambda r: (r["system"], r.get("size", 0)))
        out.append("\n## Benchmark 2 — Bulk Import\n")
        rows = []
        for r in results:
            rows.append([
                r["system"], r.get("size", "-"),
                _pm(r, "import_secs", 3), _pm(r, "records_per_sec"),
                r.get("import_errors", "-"), r.get("peak_mem_mb", "-"),
                r.get("runs", 1),
            ])
        out.append(_md_table(
            ["System", "Records", "Import (s)", "Records/sec", "Errors",
             "Peak mem (MB)", "Runs"], rows))
        out.append(_bulk_linearity_note(results))

    # Generic dump for the remaining benchmarks.
    titles = {
        "b03_propagation": "Benchmark 3 — End-to-End Propagation",
        "b04_axfr": "Benchmark 4 — AXFR Performance",
        "b05_ixfr": "Benchmark 5 — IXFR Performance",
        "b06_large_zone": "Benchmark 6 — Large Zone Performance",
    }
    for key, title in titles.items():
        if key not in data:
            continue
        results = _rows(data, key)
        if not results:
            continue
        out.append(f"\n## {title}\n")
        headers = _union_headers(results)
        rows = [[r.get(h, "-") for h in headers] for r in results]
        out.append(_md_table(headers, rows))

    if "b07_database" in data:
        out.append(_render_b07(_rows(data, "b07_database")))

    if "b08_query_perf" in data:
        results = _rows(data, "b08_query_perf")

        def _ok(r):
            """Select query runs with a QPS measurement for numeric comparisons.

            Failed runs lack QPS, so they are reported separately from the
            numeric table and the overhead calculation, which divides by QPS.
            """
            return r.get("status") != "FAILED" and r.get("qps") is not None

        failed = [r for r in results if not _ok(r)]
        ok = [r for r in results if _ok(r)]
        # A run whose every timed query failed reports qps 0.0 without being
        # FAILED; it is listed, but cannot anchor or receive a comparison.
        comparable = {r["system"]: r for r in ok if r["qps"] > 0}
        out.append("\n## Benchmark 8 — DNS Query Performance\n")
        rows = []
        for r in ok:
            rows.append([r["system"], r.get("qps", "-"), r.get("avg_latency_ms", "-"),
                         r.get("p95_ms", "-"), r.get("p99_ms", "-"),
                         _b08_query_delta(r, comparable)])
        out.append(_md_table(
            ["Server", "QPS", "Avg latency (ms)", "p95 (ms)", "p99 (ms)",
             "QPS vs. same server standalone"], rows))
        if failed:
            out.append("\n> ⚠️ Failed runs: " +
                       ", ".join(f'{r.get("system", "?")} ({r.get("error", "?")})'
                                 for r in failed) + "\n")
        out.append(_b08_conclusion(comparable))

    if "b09_resource_usage" in data:
        results = _rows(data, "b09_resource_usage")
        if results:
            out.append("\n## Benchmark 9 — Resource Usage\n")
            headers = _union_headers(results)
            rows = [[r.get(h, "-") for h in headers] for r in results]
            out.append(_md_table(headers, rows))
    return "\n".join(out)


def _write_graphs(data: dict) -> None:
    """Write the comparison graph images when the plotting dependency is available."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    def write_bar_chart(fname: str, title: str, labels: list[str],
                        values: list[float], ylabel: str):
        """Write one benchmark metric's bar chart to a PNG."""
        if not labels:
            return
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.bar(labels, values, color="#3b82f6")
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(GRAPHS_DIR / fname, dpi=120)
        plt.close(fig)

    if "b01_crud_tps" in data:
        rs = _rows(data, "b01_crud_tps")
        write_bar_chart("b01_create_tps.png", "Record Create TPS",
            [r["system"] for r in rs], [r.get("create_tps", 0) for r in rs], "TPS")
        write_bar_chart("b01_read_tps.png", "Record Read TPS",
            [r["system"] for r in rs], [r.get("read_tps", 0) for r in rs], "TPS")
    if "b08_query_perf" in data:
        rs = _rows(data, "b08_query_perf")
        write_bar_chart("b08_qps.png", "DNS Query Throughput (QPS)",
            [r["system"] for r in rs], [r.get("qps", 0) for r in rs], "QPS")
    if "b03_propagation" in data:
        rs = _rows(data, "b03_propagation")
        write_bar_chart("b03_visible_p95.png", "DNS-Visible Latency p95 (create -> answerable)",
            [r["system"] for r in rs], [r.get("visible_p95_ms", 0) for r in rs], "ms")
    if "b02_bulk_import" in data:
        # Largest-size row per system.
        by_sys: dict[str, dict] = {}
        for r in _rows(data, "b02_bulk_import"):
            prev = by_sys.get(r["system"])
            if prev is None or r.get("size", 0) >= prev.get("size", 0):
                by_sys[r["system"]] = r
        rs = list(by_sys.values())
        write_bar_chart("b02_records_per_sec.png", "Bulk Import Throughput (records/sec)",
            [r["system"] for r in rs], [r.get("records_per_sec", 0) for r in rs],
            "records/sec")
