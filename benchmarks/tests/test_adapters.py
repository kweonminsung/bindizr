"""Adapter failures must reach workload results without committing candidate state."""
import asyncio
from contextlib import nullcontext
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import time
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adapters import registry
from runners import b02_bulk_import


class AdapterTests(IsolatedAsyncioTestCase):
    def setUp(self):
        """Build record fixtures for adapter writes."""
        self.record = {"name": "new", "type": "A", "value": "192.0.2.1", "ttl": 60}
        self.old = {"name": "old", "type": "A", "value": "192.0.2.2", "ttl": 60}

    def adapters(self):
        """Construct file-backed adapters without starting their containers."""
        return [registry.build_adapter(key, {}, "unit-adapters")
                for key in ("bind9_rndc", "bind9_native", "coredns")]

    async def test_failed_mutations_do_not_publish_candidate_state(self):
        """Failed mutations must preserve the last published snapshot."""
        for adapter in self.adapters():
            adapter.records = {"old|A": self.old}
            with self.subTest(adapter=adapter.key), \
                    patch.object(adapter, "_flush_and_reload", AsyncMock(return_value=False)):
                with self.assertRaises(RuntimeError):
                    await adapter.create_record("bench.example", self.record)
                self.assertFalse(await adapter.update_record("bench.example", "old|A", {"ttl": 120}))
                self.assertFalse(await adapter.delete_record("bench.example", "old|A"))
                with self.assertRaises(RuntimeError):
                    await adapter.delete_zone("bench.example")
                await adapter.import_records("bench.example", [self.record])
                self.assertEqual(adapter.bulk_errors, 1)
                self.assertEqual(adapter.records, {"old|A": self.old})

    async def test_failed_bulk_reload_yields_zero_throughput(self):
        """A failed reload must count as an import error with zero throughput."""
        sampler = Mock(summary=lambda: {})
        for adapter in self.adapters():
            with self.subTest(adapter=adapter.key), \
                    patch.object(adapter, "delete_zone", AsyncMock()), \
                    patch.object(adapter, "create_zone", AsyncMock()), \
                    patch.object(adapter, "_flush_and_reload", AsyncMock(return_value=False)):
                scope = nullcontext(sampler)
                scope.summary = sampler.summary
                with patch.object(b02_bulk_import, "sampler_for", return_value=scope):
                    result = await b02_bulk_import._measure(
                        adapter, "bench.example", 1, adapter.key,
                        lambda: adapter.import_records("bench.example", [self.record]),
                        lambda: adapter.bulk_errors)
                self.assertEqual(result["import_errors"], 1)
                self.assertEqual(result["records_per_sec"], 0)

    async def test_bind9_only_publishes_successful_reloads_and_resets_errors(self):
        """Publish accepted snapshots and clear bulk errors after success."""
        adapter = self.adapters()[0]
        adapter.records = {"old|A": self.old}
        # Failure writing the file and failure requesting reload both preserve state.
        for outcomes in ([False], [True, False]):
            with patch.object(adapter, "_run", AsyncMock(side_effect=outcomes)):
                await adapter.import_records("bench.example", [self.record])
            self.assertEqual(adapter.bulk_errors, 1)
            self.assertEqual(adapter.records, {"old|A": self.old})

        with patch.object(adapter, "_run", AsyncMock(return_value=True)):
            await adapter.import_records("bench.example", [self.record])
            self.assertEqual(adapter.bulk_errors, 0)
            self.assertEqual(set(adapter.records), {"old|A", "new|A"})
            self.assertTrue(await adapter.update_record("bench.example", "old|A", {"ttl": 120}))
            self.assertEqual(adapter.records["old|A"]["ttl"], 120)
            self.assertTrue(await adapter.delete_record("bench.example", "new|A"))
            await adapter.delete_zone("bench.example")
            self.assertEqual(adapter.records, {})

    async def test_bind9_serializes_concurrent_candidate_writes(self):
        """Concurrent writes must retain both records."""
        adapter = self.adapters()[0]
        entered, release = asyncio.Event(), asyncio.Event()

        async def write(*args, **kwargs):
            """Hold the reload until both writers are scheduled."""
            entered.set()
            await release.wait()
            return True

        with patch.object(adapter, "_run", side_effect=write):
            first = asyncio.create_task(adapter.create_record("bench.example", self.record))
            await asyncio.wait_for(entered.wait(), 2)
            second = asyncio.create_task(adapter.create_record("bench.example", self.old))
            release.set()
            await asyncio.gather(first, second)
        self.assertEqual(set(adapter.records), {"old|A", "new|A"})

    async def test_coredns_copy_failure_and_cancel_preserve_state(self):
        """Failed or cancelled copies preserve the published snapshot."""
        adapter = self.adapters()[2]
        adapter.records = {"old|A": self.old}
        from lib import process

        for failure in (None, asyncio.CancelledError()):
            copies = []

            async def copy(*command, **kwargs):
                """Simulate a failed or cancelled copy."""
                copies.append(command)
                self.assertEqual(command[2], "-")
                self.assertIsInstance(kwargs["input"], bytes)
                if failure is not None:
                    raise failure
                return subprocess.CompletedProcess(command, 1)

            with patch.object(process, "run", side_effect=copy):
                if failure is None:
                    await adapter.import_records("bench.example", [self.record])
                    self.assertEqual(adapter.bulk_errors, 1)
                else:
                    with self.assertRaises(asyncio.CancelledError):
                        await adapter.create_record("bench.example", self.record)
            self.assertTrue(copies)
            self.assertEqual(adapter.records, {"old|A": self.old})

    async def test_coredns_stream_preserves_zone_content_permissions_and_reload_time(self):
        """Preserve UTF-8 zone data, container read access and reload timestamps."""
        adapter = self.adapters()[2]
        adapter.cid = "unit-coredns"
        record = {"name": "txt", "type": "TXT", "value": '한글 "quote"', "ttl": 60}
        from lib import process, zonefile

        before = time.time()
        with patch.object(process, "run", AsyncMock(return_value=subprocess.CompletedProcess([], 0))) as copy, \
                patch.object(adapter, "_query_soa_serial", AsyncMock(return_value=2)):
            await adapter.create_record("bench.example", record)

        self.assertEqual(copy.call_args.args, ("docker", "cp", "-", "unit-coredns:/zones"))
        with tarfile.open(fileobj=io.BytesIO(copy.call_args.kwargs["input"])) as archive:
            self.assertEqual(archive.getnames(), ["bench.example.zone"])
            member = archive.getmember("bench.example.zone")
            self.assertTrue(member.isfile())
            self.assertEqual(member.mode, 0o644)
            self.assertGreaterEqual(member.mtime, before)
            self.assertLessEqual(member.mtime, time.time())
            expected = zonefile.build_zone_file("bench.example", 2, [record]).encode("utf-8")
            self.assertEqual(member.size, len(expected))
            self.assertEqual(archive.extractfile(member).read(), expected)
        self.assertEqual(adapter.records, {"txt|TXT": record})

    async def test_coredns_publishes_only_after_observing_the_new_serial(self):
        """Publish CoreDNS candidates only once the new serial is visible."""
        adapter = self.adapters()[2]
        adapter.records = {"old|A": self.old}
        candidate = {"new|A": self.record}
        from lib import process

        async def visible():
            """Report the new serial while checking the old snapshot remains published."""
            self.assertEqual(adapter.records, {"old|A": self.old})
            return adapter.serial

        with patch.object(process, "run", AsyncMock(return_value=subprocess.CompletedProcess([], 0))), \
                patch.object(adapter, "_query_soa_serial", side_effect=visible):
            await adapter.import_records("bench.example", [self.record])
        self.assertEqual(adapter.bulk_errors, 0)
        self.assertEqual(set(adapter.records), {"old|A", "new|A"})

        with patch.object(process, "run", AsyncMock(return_value=subprocess.CompletedProcess([], 0))):
            self.assertFalse(await adapter._flush_and_reload(candidate, timeout=0))
        self.assertEqual(set(adapter.records), {"old|A", "new|A"})
