"""Aggregate `write_result` rows into performance.{json,csv,md} under results_<timestamp>/.

Render graphs/*.png when matplotlib is available.
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
    path = RAW_DIR / f"{benchmark}.json"
    payload: dict[str, Any] = {"benchmark": benchmark, "results": []}

    if path.exists():
        payload = json.loads(path.read_text())

    payload["results"].append(result)
    path.write_text(json.dumps(payload, indent=2))


def _load_all() -> dict[str, dict]:
    """Load all saved raw benchmark result files."""
    data: dict[str, dict] = {}
    if RAW_DIR.exists():
        for file in sorted(RAW_DIR.glob("*.json")):
            payload = json.loads(file.read_text())
            data[payload["benchmark"]] = payload
    return data


def _render_markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Render headers and rows as a Markdown table."""
    line = "| " + " | ".join(headers) + " |\n"
    line += "| " + " | ".join("---" for _ in headers) + " |\n"
    for row in rows:
        line += "| " + " | ".join(str(cell) for cell in row) + " |\n"
    return line


def write_report(env: dict, config: dict) -> None:
    """Write the combined JSON, CSV, Markdown, and graph reports."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    data = _load_all()

    full = {"environment": env, "config_seed": config.get("seed"), "benchmarks": data}
    (RESULTS_DIR / "performance.json").write_text(json.dumps(full, indent=2))

    csv_rows: list[dict] = []

    for name, payload in data.items():
        for result in payload["results"]:
            row = {"benchmark": name}
            row.update({key: value for key, value in result.items() if not isinstance(value, (dict, list))})
            csv_rows.append(row)

    if csv_rows:
        keys: list[str] = []

        for result in csv_rows:
            for key in result:
                if key not in keys:
                    keys.append(key)

        with open(RESULTS_DIR / "performance.csv", "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            writer.writerows(csv_rows)

    (RESULTS_DIR / "performance.md").write_text(_render_markdown(env, data))
    _write_graphs(data)


# Fields that identify a distinct measurement (not metrics to average over).
# `status` is a dimension so a FAILED row is never merged into a successful one
# sharing the other fields.
DIMENSION_FIELDS = ("system", "backend", "size", "changes", "status")


def _aggregate(rows: list[dict]) -> list[dict]:
    """Report mean, sample deviation and count by dimension, averaging only complete numeric metrics."""
    groups: dict[tuple, list[dict]] = {}

    for row in rows:
        groups.setdefault(tuple(str(row.get(field)) for field in DIMENSION_FIELDS), []).append(row)

    aggregated = []

    for group in groups.values():
        base = group[0]
        aggregate: dict = {}

        for key in base:
            values = [row.get(key) for row in group]
            numeric = [value for value in values
                       if isinstance(value, (int, float)) and not isinstance(value, bool)]

            if key not in DIMENSION_FIELDS and numeric and len(numeric) == len(values):
                aggregate[key] = round(sum(numeric) / len(numeric), 3)
                aggregate[f"{key}_std"] = round(stdev(numeric), 3) if len(numeric) > 1 else 0.0
            else:
                aggregate[key] = base.get(key)

        if len(group) > 1:
            aggregate["runs"] = len(group)

        aggregated.append(aggregate)

    return aggregated


def _display_metric(row: dict, key: str, prec: int = 1, default: Any = "-") -> str:
    """Render a metric as `mean ± std` (std omitted when 0 / single run)."""
    mean = row.get(key)

    if not isinstance(mean, (int, float)) or isinstance(mean, bool):
        return default

    std = row.get(f"{key}_std", 0) or 0

    if std:
        return f"{mean:.{prec}f} ± {std:.{prec}f}"

    return f"{mean:.{prec}f}"


def _render_bulk_linearity_note(rows: list[dict]) -> str:
    """Per-series 10k→100k scaling: import time should grow ~10x for 10x records."""
    by_sys: dict[str, dict[int, float]] = {}

    for row in rows:
        secs = row.get("import_secs")
        if isinstance(row.get("size"), int) and isinstance(secs, (int, float)):
            by_sys.setdefault(row["system"], {})[row["size"]] = secs

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


def _display_b08_query_delta(row: dict, comparable: dict[str, dict]) -> str:
    """Render QPS change against a measured positive baseline, `baseline` for it, or `-` if absent."""
    standalone = comparable.get(QUERY_BASELINES.get(row["system"], ""))
    if standalone and row["system"] in comparable:
        return f'{(row["qps"] / standalone["qps"] - 1) * 100:+.1f}%'
    if row["system"] in QUERY_BASELINES.values():
        return "baseline"
    return "-"


def _render_b08_conclusion(comparable: dict[str, dict]) -> str:
    """State per-pairing overhead conclusions only for positive QPS on both sides.
    Compare each gap with the run-to-run noise tolerance."""
    within: list[str] = []
    outside: list[str] = []

    for pairing, standalone in QUERY_BASELINES.items():
        pairing_row, standalone_row = comparable.get(pairing), comparable.get(standalone)
        if not pairing_row or not standalone_row:
            continue
        delta = (pairing_row["qps"] / standalone_row["qps"] - 1) * 100
        entry = f"`{pairing}` vs `{standalone}` ({delta:+.1f}%)"
        (within if abs(delta) <= QUERY_NOISE_TOLERANCE_PCT else outside).append(entry)

    if not within and not outside:
        return ("\n> ⚠️ No-overhead conclusion unavailable: this run has no Bindizr "
                "pairing and standalone run of the same server to compare.\n")

    text = ""

    if within:
        text += ("\n> **Bindizr introduces no measurable DNS query overhead because it "
                "is outside the DNS data plane.** Queries are served by the secondary, "
                "not by Bindizr, so each pairing tracks that server run standalone: "
                + ", ".join(within)
                + f" — within the ±{QUERY_NOISE_TOLERANCE_PCT:.0f}% run-to-run tolerance.\n")

    if outside:
        text += (f"\n> ⚠️ Outside the ±{QUERY_NOISE_TOLERANCE_PCT:.0f}% noise tolerance, "
                "so this run does not support the no-overhead conclusion there: "
                + ", ".join(outside) + ".\n")

    return text


def _render_b07(rows: list[dict]) -> str:
    """Render separate Benchmark 7 tables for CRUD TPS and bulk-import time by size."""
    crud = [row for row in rows if "create_tps" in row]
    bulk = [row for row in rows if "import_secs" in row]
    failed = [row for row in rows if row.get("status") == "FAILED"]
    lines = ["\n## Benchmark 7 — Database Performance\n"]

    if crud:
        lines.append("\n### 7a — CRUD throughput by backend\n")
        crud = sorted(crud, key=lambda row: (row.get("system", ""),
                                           row.get("backend", "")))
        crud_rows = [[
            row.get("system", "-"),
            row.get("backend", "-"), _display_metric(row, "create_tps"), _display_metric(row, "read_tps"),
            _display_metric(row, "create_p95_ms", 2), _display_metric(row, "read_p95_ms", 2),
            f'{row.get("error_rate", 0) * 100:.2f}%', row.get("peak_mem_mb", "-"),
            row.get("bindizr_peak_mem_mb", "-"), row.get("db_peak_mem_mb", "-"),
            row.get("runs", 1),
        ] for row in crud]
        lines.append(_render_markdown_table(
            ["Pairing", "Backend", "Create TPS", "Read TPS", "Create p95 (ms)",
             "Read p95 (ms)", "Error Rate", "Peak mem (MB)",
             "Bindizr mem (MB)", "DB mem (MB)", "Runs"], crud_rows))
        lines.append("\n> Peak mem is the highest per-tick stack total (Bindizr "
                   "+ BIND9 + DB server, per `docker stats`). The split "
                   "columns are each container's own peak, taken at possibly "
                   "different ticks and excluding BIND9, so they need not sum "
                   "to it. sqlite runs in-process, so its DB share is 0.\n")

    if bulk:
        lines.append("\n### 7b — Bulk import by backend\n")
        bulk = sorted(bulk, key=lambda row: (row.get("system", ""),
                                           row.get("backend", ""),
                                           row.get("size", 0)))
        bulk_rows = [[
            row.get("system", "-"), row.get("backend", "-"), row.get("size", "-"),
            _display_metric(row, "import_secs", 3), _display_metric(row, "records_per_sec"),
            row.get("import_errors", "-"), row.get("peak_mem_mb", "-"),
            row.get("bindizr_peak_mem_mb", "-"), row.get("db_peak_mem_mb", "-"),
            row.get("runs", 1),
        ] for row in bulk]
        lines.append(_render_markdown_table(
            ["Pairing", "Backend", "Records", "Import (s)", "Records/sec", "Errors",
             "Peak mem (MB)", "Bindizr mem (MB)", "DB mem (MB)", "Runs"],
            bulk_rows))
        # One series per pairing and backend, so the note keys on both.
        lines.append(_render_bulk_linearity_note(
            [{**row, "system": f'{row.get("system", "-")} / {row.get("backend", "-")}'}
             for row in bulk]))

    if failed:
        lines.append("\n> ⚠️ Failed backends: " +
                   ", ".join(f'{row.get("system", "-")} / {row.get("backend")} '
                             f'({row.get("error", "?")})'
                             for row in failed) + "\n")

    return "".join(lines)


def _rows(data: dict, key: str) -> list[dict]:
    """Return aggregated rows for one benchmark when results exist."""
    return _aggregate(data[key]["results"]) if key in data else []


def _union_headers(results: list[dict]) -> list[str]:
    """Collect columns in first-seen order, including failure-only status/error keys."""
    headers: list[str] = []
    for row in results:
        for header in row:
            if not header.endswith("_std") and header not in headers:
                headers.append(header)
    return headers


def _render_markdown(env: dict, data: dict) -> str:
    """Render the environment and benchmark results as a Markdown report."""
    hardware = env["hardware"]
    lines = ["# Bindizr Benchmark Results\n"]
    lines.append("## Test Environment\n")
    lines.append(_render_markdown_table(
        ["Component", "Value"],
        [
            ["CPU", f"{hardware['cpu']} ({hardware['cpu_cores']} cores)"],
            ["Memory", f"{hardware['memory_gb']} GB"],
            ["Storage (free)", f"{hardware['storage_free_gb']} GB"],
            ["OS", env["os"]["platform"]],
            ["Docker", env["docker"]["version"]],
            ["Per-container limit", f"{env.get('limits', {}).get('cpus', '?')} CPU / "
                                    f"{env.get('limits', {}).get('memory', '?')}"],
            ["Repeats (averaged)", env.get("config", {}).get("repeats", 1)],
        ],
    ))
    lines.append("\n### Software Versions\n")
    lines.append(_render_markdown_table(["Software", "Version"],
                         [[name, version] for name, version in env["software"].items()]))

    if "b01_crud_tps" in data:
        lines.append("\n## Benchmark 1 — Record CRUD TPS\n")
        rows = []

        for row in _rows(data, "b01_crud_tps"):
            rows.append([
                row["system"], _display_metric(row, "create_tps"), _display_metric(row, "update_tps"),
                _display_metric(row, "delete_tps"), _display_metric(row, "read_tps"),
                _display_metric(row, "read_p95_ms", 2), f'{row.get("error_rate", 0) * 100:.2f}%',
                row.get("runs", 1),
            ])

        lines.append(_render_markdown_table(
            ["Product", "Create TPS", "Update TPS", "Delete TPS", "Read TPS",
             "Read p95 (ms)", "Error Rate", "Runs"], rows))

    # Curated table: mean ± std on time / throughput.
    if "b02_bulk_import" in data:
        results = sorted(_rows(data, "b02_bulk_import"),
                         key=lambda row: (row["system"], row.get("size", 0)))
        lines.append("\n## Benchmark 2 — Bulk Import\n")
        rows = []

        for row in results:
            rows.append([
                row["system"], row.get("size", "-"),
                _display_metric(row, "import_secs", 3), _display_metric(row, "records_per_sec"),
                row.get("import_errors", "-"), row.get("peak_mem_mb", "-"),
                row.get("runs", 1),
            ])

        lines.append(_render_markdown_table(
            ["System", "Records", "Import (s)", "Records/sec", "Errors",
             "Peak mem (MB)", "Runs"], rows))
        lines.append(_render_bulk_linearity_note(results))

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

        lines.append(f"\n## {title}\n")
        headers = _union_headers(results)
        rows = [[row.get(header, "-") for header in headers] for row in results]
        lines.append(_render_markdown_table(headers, rows))

    if "b07_database" in data:
        lines.append(_render_b07(_rows(data, "b07_database")))

    if "b08_query_perf" in data:
        results = _rows(data, "b08_query_perf")

        def _has_reportable_qps(row):
            """Select non-failed runs with QPS; failures are reported outside numeric comparisons."""
            return row.get("status") != "FAILED" and row.get("qps") is not None

        failed = [row for row in results if not _has_reportable_qps(row)]
        ok = [row for row in results if _has_reportable_qps(row)]
        # A run whose every timed query failed reports qps 0.0 without being
        # FAILED; it is listed, but cannot anchor or receive a comparison.
        comparable = {row["system"]: row for row in ok if row["qps"] > 0}
        lines.append("\n## Benchmark 8 — DNS Query Performance\n")
        rows = []

        for row in ok:
            rows.append([row["system"], row.get("qps", "-"), row.get("avg_latency_ms", "-"),
                         row.get("p95_ms", "-"), row.get("p99_ms", "-"),
                         _display_b08_query_delta(row, comparable)])

        lines.append(_render_markdown_table(
            ["Server", "QPS", "Avg latency (ms)", "p95 (ms)", "p99 (ms)",
             "QPS vs. same server standalone"], rows))

        if failed:
            lines.append("\n> ⚠️ Failed runs: " +
                       ", ".join(f'{row.get("system", "?")} ({row.get("error", "?")})'
                                 for row in failed) + "\n")

        lines.append(_render_b08_conclusion(comparable))

    if "b09_resource_usage" in data:
        results = _rows(data, "b09_resource_usage")
        if results:
            lines.append("\n## Benchmark 9 — Resource Usage\n")
            headers = _union_headers(results)
            rows = [[row.get(header, "-") for header in headers] for row in results]
            lines.append(_render_markdown_table(headers, rows))

    return "\n".join(lines)


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
        rows = _rows(data, "b01_crud_tps")
        write_bar_chart("b01_create_tps.png", "Record Create TPS",
            [row["system"] for row in rows], [row.get("create_tps", 0) for row in rows], "TPS")
        write_bar_chart("b01_read_tps.png", "Record Read TPS",
            [row["system"] for row in rows], [row.get("read_tps", 0) for row in rows], "TPS")

    if "b08_query_perf" in data:
        rows = _rows(data, "b08_query_perf")
        write_bar_chart("b08_qps.png", "DNS Query Throughput (QPS)",
            [row["system"] for row in rows], [row.get("qps", 0) for row in rows], "QPS")

    if "b03_propagation" in data:
        rows = _rows(data, "b03_propagation")
        write_bar_chart("b03_visible_p95.png", "DNS-Visible Latency p95 (create -> answerable)",
            [row["system"] for row in rows], [row.get("visible_p95_ms", 0) for row in rows], "ms")

    if "b02_bulk_import" in data:
        # Largest-size row per system.
        by_sys: dict[str, dict] = {}

        for row in _rows(data, "b02_bulk_import"):
            prev = by_sys.get(row["system"])
            if prev is None or row.get("size", 0) >= prev.get("size", 0):
                by_sys[row["system"]] = row

        rows = list(by_sys.values())
        write_bar_chart("b02_records_per_sec.png", "Bulk Import Throughput (records/sec)",
            [row["system"] for row in rows], [row.get("records_per_sec", 0) for row in rows],
            "records/sec")
