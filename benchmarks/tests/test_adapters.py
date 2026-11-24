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


def _http_response(status=200, data=None, message=""):
    """Build an aiohttp-style response context for adapter tests."""
    request = AsyncMock()
    request.__aenter__.return_value = Mock(
        status=status,
        json=AsyncMock(return_value=data),
        text=AsyncMock(return_value=message),
    )
    return request


class HttpAdapterTests(IsolatedAsyncioTestCase):
    zone = "bench.example"

    def adapter(self, key):
        """Construct an HTTP adapter with a mock client."""
        adapter = registry.build_adapter(key, {}, "unit-adapters")
        adapter.session = Mock()
        return adapter

    async def test_technitium_get_matches_exact_record_data(self):
        """Check the five generated record types against the server's rData fields."""
        adapter = self.adapter("technitium")

        def records(entries):
            """Wrap a list of resource records as returned by Technitium."""
            return _http_response(data={"status": "ok", "response": {"records": entries}})

        for record_type, value, matching, different in (
            ("A", "192.0.2.1", {"ipAddress": "192.0.2.1"}, {"ipAddress": "192.0.2.2"}),
            ("AAAA", "2001:db8::1", {"ipAddress": "2001:0DB8:0:0:0:0:0:1"},
             {"ipAddress": "2001:db8::2"}),
            ("CNAME", "Mail.Bench.Example.", {"cname": "mail.bench.example"},
             {"cname": "other.bench.example"}),
            ("MX", "Mail.Bench.Example.", {"exchange": "mail.bench.example", "preference": 10},
             {"exchange": "mail.bench.example", "preference": 20}),
            ("TXT", "v=Bench||1", {"text": "v=Bench||1"}, {"text": "v=bench||1"}),
        ):
            with self.subTest(record_type=record_type):
                record = {"name": "mail", "type": record_type, "value": value}
                adapter.session.get.return_value = _http_response(data={"status": "ok"})
                handle = await adapter.create_record(self.zone, record)
                found = {"name": "MAIL.BENCH.EXAMPLE.", "type": record_type, "rData": matching}
                adapter.session.get.return_value = records([
                    {**found, "name": "other.bench.example"},
                    {**found, "type": "SOA"},
                    {**found, "rData": different},
                ])
                self.assertFalse(await adapter.get_record(self.zone, handle))
                adapter.session.get.return_value = records([found])
                self.assertTrue(await adapter.get_record(self.zone, handle))
                self.assertEqual(adapter.session.get.call_args.kwargs["params"]["listZone"], "false")
                adapter.session.get.return_value = records([])
                self.assertFalse(await adapter.get_record(self.zone, handle))

    async def test_technitium_zone_setup_and_cleanup_check_api_status(self):
        """Reject setup failures and allow only the requested zone's absence during cleanup."""
        adapter = self.adapter("technitium")
        refused = _http_response(data={"status": "error", "errorMessage": "Access was denied."})
        adapter.session.get.return_value = refused
        with self.assertRaisesRegex(RuntimeError, "/zones/create.*Access was denied"):
            await adapter.create_zone(self.zone)
        self.assertEqual(adapter.session.get.call_count, 1)

        adapter.session.get.side_effect = [_http_response(data={"status": "ok"}), refused]
        with self.assertRaisesRegex(RuntimeError, "/zones/options/set.*Access was denied"):
            await adapter.create_zone(self.zone)
        adapter.session.get.side_effect = None

        adapter.session.get.return_value = _http_response(
            data={"status": "error", "errorMessage": f"No such zone was found: {self.zone}"},
        )
        await adapter.delete_zone(self.zone)
        adapter.session.get.return_value = refused
        with self.assertRaisesRegex(RuntimeError, "/zones/delete.*Access was denied"):
            await adapter.delete_zone(self.zone)
        adapter.session.get.return_value = _http_response(status=503, message="unavailable")
        with self.assertRaisesRegex(RuntimeError, "/zones/delete 503"):
            await adapter.delete_zone(self.zone)

    async def test_technitium_record_delete_distinguishes_absence_from_failure(self):
        """Return False for a missing record and surface other API errors."""
        adapter = self.adapter("technitium")
        handle = "mail.bench.example||A||192.0.2.1||"
        adapter.session.get.return_value = _http_response(data={
            "status": "error", "errorMessage": "Cannot delete record: no such record exists.",
        })
        self.assertFalse(await adapter.delete_record(self.zone, handle))
        adapter.session.get.return_value = _http_response(
            data={"status": "error", "errorMessage": "Access was denied."},
        )
        with self.assertRaisesRegex(RuntimeError, "/zones/records/delete.*Access was denied"):
            await adapter.delete_record(self.zone, handle)

    async def test_zone_cleanup_surfaces_bindizr_and_powerdns_failures(self):
        """Only a successful deletion or a missing zone permits the next benchmark round."""
        for key, status, not_found in (("bindizr", 200, {"code": "ZONE_NOT_FOUND"}),
                                       ("powerdns", 204, None)):
            with self.subTest(adapter=key):
                adapter = self.adapter(key)
                adapter.session.delete.return_value = _http_response(status=status)
                await adapter.delete_zone(self.zone)
                adapter.session.delete.return_value = _http_response(status=404, data=not_found)
                await adapter.delete_zone(self.zone)
                adapter.session.delete.return_value = _http_response(status=500, message="failed")
                with self.assertRaisesRegex(RuntimeError, "delete_zone 500: failed"):
                    await adapter.delete_zone(self.zone)

        adapter = self.adapter("bindizr")
        adapter.session.delete.return_value = _http_response(
            status=404, data={"code": "UNEXPECTED"}, message="unexpected",
        )
        with self.assertRaisesRegex(RuntimeError, "delete_zone 404: unexpected"):
            await adapter.delete_zone(self.zone)

    async def test_powerdns_get_matches_exact_rrset(self):
        """Respect the RRset handle when the API returns different owners or types."""
        adapter = self.adapter("powerdns")
        name = "mail.bench.example."
        handle = f"{name}|A"
        rrset = {"name": name.upper(), "type": "A", "records": [{"content": "192.0.2.1"}]}
        adapter.session.get.return_value = _http_response(data={"rrsets": [
            {**rrset, "name": "other.bench.example."},
            {**rrset, "type": "AAAA"},
            {**rrset, "records": []},
        ]})
        self.assertFalse(await adapter.get_record(self.zone, handle))
        adapter.session.get.return_value = _http_response(data={"rrsets": [rrset]})
        self.assertTrue(await adapter.get_record(self.zone, handle))
        self.assertEqual(adapter.session.get.call_args.kwargs["params"],
                         {"rrset_name": name, "rrset_type": "A"})

    async def test_powerdns_zone_setup_distinguishes_conflicts_from_invalid_requests(self):
        """Allow an existing zone and fail on a rejected creation."""
        adapter = self.adapter("powerdns")
        adapter.session.post.return_value = _http_response(status=409)
        await adapter.create_zone(self.zone)
        adapter.session.post.return_value = _http_response(status=422, message="invalid request")
        with self.assertRaisesRegex(RuntimeError, "create_zone 422: invalid request"):
            await adapter.create_zone(self.zone)


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
        """Verify that failed mutations preserve the last published snapshot."""
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

    async def test_file_adapters_own_records_after_create_and_import(self):
        """Verify that caller mutations cannot change accepted snapshots or later TTL-only writes."""
        from lib import zonefile

        for operation in ("create", "import"):
            for during_publication in (False, True):
                for adapter in self.adapters():
                    record = dict(self.record)
                    published = []
                    entered, release = asyncio.Event(), asyncio.Event()

                    async def publish(candidate):
                        """Capture the published bytes before allowing the snapshot to advance."""
                        published.append(zonefile.build_zone_file(
                            "bench.example", adapter.serial, candidate.values()))
                        entered.set()
                        if during_publication:
                            await release.wait()
                        return True

                    with self.subTest(adapter=adapter.key, operation=operation,
                                      during_publication=during_publication), \
                            patch.object(adapter, "_flush_and_reload", side_effect=publish):
                        mutation = (adapter.create_record("bench.example", record)
                                    if operation == "create"
                                    else adapter.import_records("bench.example", [record]))
                        if during_publication:
                            task = asyncio.create_task(mutation)
                            try:
                                await asyncio.wait_for(entered.wait(), 2)
                                record["value"] = "192.0.2.99"
                            finally:
                                release.set()
                            await task
                        else:
                            await mutation
                            record["value"] = "192.0.2.99"

                        self.assertEqual(adapter.records["new|A"]["value"], "192.0.2.1")
                        self.assertEqual(len(published), 1)
                        self.assertIn("new 60 IN A 192.0.2.1", published[0])
                        self.assertTrue(await adapter.update_record(
                            "bench.example", "new|A", {"ttl": 120}))
                        self.assertIn("new 120 IN A 192.0.2.1", published[1])

    async def test_failed_bulk_reload_yields_zero_throughput(self):
        """Verify that a failed reload counts as an import error with zero throughput."""
        sampler = Mock(summary=lambda: {})
        for adapter in self.adapters():
            with self.subTest(adapter=adapter.key), \
                    patch.object(adapter, "delete_zone", AsyncMock()), \
                    patch.object(adapter, "create_zone", AsyncMock()), \
                    patch.object(adapter, "_flush_and_reload", AsyncMock(return_value=False)):
                scope = nullcontext(sampler)
                scope.summary = sampler.summary
                with patch.object(b02_bulk_import, "load_sampler", return_value=scope):
                    result = await b02_bulk_import._measure(
                        adapter, "bench.example", 1, adapter.key,
                        lambda: adapter.import_records("bench.example", [self.record]),
                        lambda: adapter.bulk_errors)
                self.assertEqual(result["import_errors"], 1)
                self.assertEqual(result["records_per_sec"], 0)

    async def test_bind9_only_publishes_successful_reloads_and_resets_errors(self):
        """Verify that Bind9 publishes accepted snapshots and clears bulk errors after success."""
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
        """Verify that concurrent writes retain both records."""
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

    async def test_every_file_adapter_serializes_and_publishes_accepted_candidates(self):
        """Verify that file adapters share mutation semantics while retaining publisher readiness rules."""
        for adapter in self.adapters():
            entered, release = asyncio.Event(), asyncio.Event()

            async def publish(candidate):
                """Hold publication before the common snapshot is advanced."""
                entered.set()
                await release.wait()
                return True

            with self.subTest(adapter=adapter.key), \
                    patch.object(adapter, "_flush_and_reload", side_effect=publish):
                first = asyncio.create_task(adapter.create_record("bench.example", self.record))
                second = None
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    self.assertEqual(adapter.records, {})
                    second = asyncio.create_task(adapter.create_record("bench.example", self.old))
                finally:
                    release.set()
                    await asyncio.gather(*(task for task in (first, second) if task is not None))
                self.assertEqual(set(adapter.records), {"old|A", "new|A"})

    async def test_cancelled_publication_preserves_state_and_releases_the_write_lock(self):
        """Verify that cancelled publication preserves state and permits later writes."""
        for adapter in self.adapters():
            adapter.records = {"old|A": self.old}
            entered = asyncio.Event()

            async def pending(candidate):
                """Keep the concrete publisher pending until cancellation."""
                entered.set()
                await asyncio.Future()

            with self.subTest(adapter=adapter.key), \
                    patch.object(adapter, "_flush_and_reload", side_effect=pending):
                task = asyncio.create_task(adapter.create_record("bench.example", self.record))
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                finally:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertEqual(adapter.records, {"old|A": self.old})
            with patch.object(adapter, "_flush_and_reload", AsyncMock(return_value=True)):
                await asyncio.wait_for(adapter.create_record("bench.example", self.record), 2)
            self.assertEqual(set(adapter.records), {"old|A", "new|A"})

    async def test_coredns_copy_failure_and_cancel_preserve_state(self):
        """Verify that failed or cancelled CoreDNS copies preserve the published snapshot."""
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
        """Verify that CoreDNS streaming preserves UTF-8 zone data, read access and reload timestamps."""
        adapter = self.adapters()[2]
        adapter.container_id = "unit-coredns"
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
        """Verify that CoreDNS publishes a candidate only after its serial is visible."""
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
