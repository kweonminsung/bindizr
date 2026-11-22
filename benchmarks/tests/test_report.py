"""Keep measured values, failed runs and raw samples consistent across benchmark reports."""
import csv
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import report


class ReportTests(TestCase):
    def setUp(self):
        """Use disposable report files and capture plotting calls without requiring matplotlib."""
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        paths = patch.multiple(report, RESULTS_DIR=root, RAW_DIR=root / "raw", GRAPHS_DIR=root / "graphs")
        paths.start()
        self.addCleanup(paths.stop)
        report.RAW_DIR.mkdir()
        self.figure, self.axis = MagicMock(), MagicMock()
        matplotlib = ModuleType("matplotlib")
        matplotlib.use = MagicMock()
        self.pyplot = ModuleType("matplotlib.pyplot")
        self.pyplot.subplots = MagicMock(return_value=(self.figure, self.axis))
        self.pyplot.close = MagicMock()
        modules = patch.dict(sys.modules, {"matplotlib": matplotlib, "matplotlib.pyplot": self.pyplot})
        modules.start()
        self.addCleanup(modules.stop)
        self.environment = {
            "hardware": {"cpu": "test", "cpu_cores": 1, "memory_gb": 1, "storage_free_gb": 1},
            "os": {"platform": "test"}, "docker": {"version": "test"}, "software": {},
        }

    def write_raw(self, benchmark, rows):
        """Write the raw samples a report run reads for one benchmark."""
        (report.RAW_DIR / f"{benchmark}.json").write_text(json.dumps({"benchmark": benchmark, "results": rows}))

    def test_query_table_and_graph_preserve_zero_and_exclude_unmeasured_runs(self):
        """Verify that repeated measurements agree across views while raw files retain every failure."""
        rows = [
            {"system": "measured", "qps": 1000},
            {"system": "measured", "qps": 3000},
            {"system": "zero", "qps": 0},
            {"system": "failed", "status": "FAILED", "error": "propagation timeout"},
            {"system": "failed-with-metric", "status": "FAILED", "qps": 999},
            {"system": "missing", "qps": None},
            {"system": "boolean", "qps": True},
        ]
        self.write_raw("b08_query_perf", rows)

        with patch.object(report, "_aggregate", wraps=report._aggregate) as aggregate:
            report.write_report(self.environment, {"seed": 7})

        self.assertEqual(aggregate.call_count, 1, "rendering another view must reuse the same aggregation")
        self.assertEqual(self.axis.bar.call_args.args, (["measured", "zero"], [2000.0, 0.0]))
        markdown = (report.RESULTS_DIR / "performance.md").read_text()
        self.assertIn("| measured | 2000.0 |", markdown)
        self.assertIn("| zero | 0.0 |", markdown)
        self.assertIn("Failed runs: failed (propagation timeout)", markdown)
        for name in ("failed", "failed-with-metric", "missing", "boolean"):
            with self.subTest(system=name):
                self.assertNotIn(f"| {name} |", markdown)
        raw = json.loads((report.RESULTS_DIR / "performance.json").read_text())
        self.assertEqual(raw["benchmarks"]["b08_query_perf"]["results"], rows)
        with (report.RESULTS_DIR / "performance.csv").open(newline="") as file:
            csv_rows = list(csv.DictReader(file))
        self.assertEqual(len(csv_rows), len(rows))
        self.assertEqual(csv_rows[3]["status"], "FAILED")
        self.assertEqual(csv_rows[3]["qps"], "")

    def test_charts_choose_measured_metrics_before_selecting_largest_bulk_size(self):
        """Verify that missing metrics and failed larger imports cannot replace measured chart values."""
        self.write_raw("b01_crud_tps", [
            {"system": "create", "create_tps": 10},
            {"system": "read", "read_tps": 20},
            {"system": "failed", "status": "FAILED", "create_tps": 99, "read_tps": 99},
        ])
        self.write_raw("b02_bulk_import", [
            {"system": "bulk", "size": 100, "records_per_sec": 30},
            {"system": "bulk", "size": 200, "records_per_sec": 60},
            {"system": "bulk", "size": 1000, "status": "FAILED"},
            {"system": "bulk-zero", "size": 1000, "records_per_sec": 0},
        ])
        self.write_raw("b03_propagation", [
            {"system": "measured", "visible_p95_ms": 12},
            {"system": "missing", "visible_p95_ms": None},
            {"system": "failed", "status": "FAILED", "visible_p95_ms": 99},
        ])

        report.write_report(self.environment, {})

        charts = {saved.args[0].name: bars.args for saved, bars in
                  zip(self.figure.savefig.call_args_list, self.axis.bar.call_args_list)}
        self.assertEqual(charts, {
            "b01_create_tps.png": (["create"], [10.0]),
            "b01_read_tps.png": (["read"], [20.0]),
            "b02_records_per_sec.png": (["bulk", "bulk-zero"], [60.0, 0.0]),
            "b03_visible_p95.png": (["measured"], [12.0]),
        })

    def test_failed_queries_leave_a_failure_report_without_a_zero_qps_chart(self):
        """Verify that an entirely unmeasured run is reported without fabricating a numeric result."""
        self.write_raw("b08_query_perf", [{"system": "failed", "status": "FAILED", "error": "timeout"}])

        report.write_report(self.environment, {})

        self.pyplot.subplots.assert_not_called()
        self.assertIn("Failed runs: failed (timeout)", (report.RESULTS_DIR / "performance.md").read_text())
