"""Verify transfer completion and cancellation through real loopback dig exchanges."""
import asyncio
from contextlib import nullcontext, redirect_stdout
import io
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import dig, process
from runners import b04_axfr, b05_ixfr, b06_large_zone


def wire_name(name):
    """Encode the fixture's fixed ASCII names."""
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def soa(serial):
    """Build one uncompressed SOA for the owned test zone."""
    data = wire_name("ns.bench.example") + wire_name("hostmaster.bench.example")
    data += struct.pack("!IIIII", serial, 60, 60, 3600, 60)
    return wire_name("bench.example") + struct.pack("!HHIH", 6, 1, 60, len(data)) + data


def address(last_octet):
    """Build one A record for a transfer fixture."""
    return wire_name("host.bench.example") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, last_octet])


class DigTests(IsolatedAsyncioTestCase):
    async def peer(self, records, rcode=0, release=None):
        """Own a loopback TCP peer and all accepted connections for this test."""
        if shutil.which("dig") is None:
            self.skipTest("dig is required for independent transfer inspection")
        requests = asyncio.Queue()
        tasks = set()

        async def serve(reader, writer):
            """Answer one query, optionally holding it until cancellation is observed."""
            task = asyncio.current_task()
            tasks.add(task)
            try:
                length = struct.unpack("!H", await reader.readexactly(2))[0]
                query = await reader.readexactly(length)
                requests.put_nowait(query)
                if release is not None:
                    await release.wait()
                end = 12
                while query[end]:
                    end += query[end] + 1
                end += 5
                message = query[:2] + struct.pack("!HHHHH", 0x8400 | rcode, 1, len(records), 0, 0)
                message += query[12:end] + b"".join(records)
                writer.write(struct.pack("!H", len(message)) + message)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                tasks.discard(task)

        server = await asyncio.start_server(serve, "127.0.0.1", 0)

        async def cleanup():
            """Close the fixture listener and join every accepted task."""
            server.close()
            await server.wait_closed()
            pending = list(tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        self.addAsyncCleanup(cleanup)
        return server.sockets[0].getsockname()[1], requests

    async def test_actual_axfr_and_ixfr_completion_shapes(self):
        """Keep full, empty, SOA-only, delta and AXFR-fallback transfers valid."""
        cases = [
            ("full", [soa(3), address(1), soa(3)], None),
            ("empty", [soa(3), soa(3)], None),
            ("soa-only", [soa(3)], 3),
            ("delta", [soa(3), soa(2), address(1), soa(3), address(2), soa(3)], 2),
            ("fallback", [soa(3), address(1), soa(3)], 2),
        ]
        for name, records, serial in cases:
            with self.subTest(shape=name):
                port, _ = await self.peer(records)
                if serial is None:
                    elapsed, count, size = await dig.axfr("bench.example", "127.0.0.1", port, 1)
                else:
                    elapsed, count, size = await dig.ixfr("bench.example", "127.0.0.1", port, serial, 1)
                self.assertGreater(elapsed, 0)
                self.assertEqual(count, len(records))
                self.assertGreater(size, 0)

    async def test_actual_incomplete_and_mismatched_transfers_are_rejected(self):
        """Reject early EOF, wrong closing SOA and refused transfers even with exit zero."""
        for records, rcode in [([soa(3), address(1)], 0), ([soa(3), address(1), soa(4)], 0), ([], 5)]:
            with self.subTest(records=len(records), rcode=rcode):
                port, _ = await self.peer(records, rcode)
                with self.assertRaises(dig.TransferError) as failure:
                    await dig.axfr("bench.example", "127.0.0.1", port, 1)
                self.assertEqual(failure.exception.rcode, "REFUSED" if rcode else None)
                self.assertIsNone(await dig.count_axfr_records("bench.example", "127.0.0.1", port, 1))

    async def test_failed_command_and_inconsistent_completion_never_measure(self):
        """Require a successful command and an exact completed record count."""
        text = ("bench.example. 60 IN SOA ns.bench.example. hostmaster.bench.example. 3 60 60 3600 60\n"
                "bench.example. 60 IN SOA ns.bench.example. hostmaster.bench.example. 3 60 60 3600 60\n"
                ";; XFR size: 2 records (messages 1, bytes 100)\n")
        for output, code in [(text, 7), (text.replace("2 records", "3 records"), 0), ("", 0)]:
            with self.subTest(exit_code=code, output=output), patch.object(process, "run", AsyncMock(
                    return_value=subprocess.CompletedProcess([], code, output.encode(), b""))):
                with self.assertRaises(dig.TransferError):
                    await dig.axfr("bench.example", "127.0.0.1", 1, 1)
        timeout = subprocess.TimeoutExpired("dig", 1)
        with patch.object(process, "run", AsyncMock(side_effect=timeout)):
            with self.assertRaises(dig.TransferError) as failure:
                await dig.axfr("bench.example", "127.0.0.1", 1, 1)
        self.assertIs(failure.exception.__cause__, timeout)

    async def test_reset_requires_explicit_unserved_response_or_complete_apex(self):
        """Separate reset readiness from unavailable or refused transfer measurements."""
        for records, rcode in [([soa(3), soa(3)], 0), ([], 3), ([], 9)]:
            port, _ = await self.peer(records, rcode)
            self.assertTrue(await dig.zone_is_cleared("bench.example", "127.0.0.1", port, 2, 1))
        failure = dig.TransferError("bench.example", "127.0.0.1", 1, "AXFR", "refused", "REFUSED")
        for status, expected in [("NOERROR", False), ("SERVFAIL", False), ("NXDOMAIN", True),
                                 ("NOTAUTH", True), ("REFUSED", True)]:
            response = f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n".encode()
            with self.subTest(status=status), patch.object(dig, "axfr", AsyncMock(side_effect=failure)), \
                    patch.object(process, "run", AsyncMock(return_value=subprocess.CompletedProcess([], 0, response, b""))):
                self.assertEqual(await dig.zone_is_cleared("bench.example", "127.0.0.1", 1, 2), expected)
        with patch.object(dig, "axfr", AsyncMock(side_effect=failure)), \
                patch.object(process, "run", AsyncMock(side_effect=subprocess.TimeoutExpired("dig", 1))):
            self.assertFalse(await dig.zone_is_cleared("bench.example", "127.0.0.1", 1, 2))

    async def test_visibility_poll_compares_whole_answers(self):
        """Preserve exact-value matching while polling without an executor thread."""
        with patch.object(dig, "query", AsyncMock(side_effect=[
                (True, 0, "192.0.2.10"), (True, 0, "192.0.2.1")])) as query:
            self.assertIsNotNone(await dig.poll_until_visible("a.example", "A", "192.0.2.1", "127.0.0.1", 1, 0, 1))
        self.assertEqual(query.await_count, 2)

    async def test_cancellation_reaps_actual_dig_before_orchestrator_teardown(self):
        """Cancel B04's real exchange and require its child to exit before teardown."""
        import orchestrator

        release = asyncio.Event()
        port, requests = await self.peer([], release=release)
        children = []
        teardown_states = []
        spawn = asyncio.create_subprocess_exec

        async def capture(*args, **kwargs):
            """Keep the actual OS process for the teardown ordering assertion."""
            child = await spawn(*args, **kwargs)
            children.append(child)
            return child

        async def teardown():
            """Capture child state exactly when fixture teardown starts."""
            teardown_states.append(bool(children) and all(child.returncode is not None for child in children))

        adapter = SimpleNamespace(setup=AsyncMock(), teardown=AsyncMock(side_effect=teardown),
                                  delete_zone=AsyncMock(), resource_services=[], compose=Mock(),
                                  xfr_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=port))
        config = dict(systems={"test": {"label": "test"}}, sizes=[1], seed=1,
                      resources={"sample_interval_secs": 0.01})
        with patch.object(orchestrator.registry, "build_adapter", return_value=adapter), \
                patch.object(asyncio, "create_subprocess_exec", side_effect=capture), \
                redirect_stdout(io.StringIO()):
            task = asyncio.create_task(orchestrator.run_one("b04_axfr", "test", config))
            try:
                await asyncio.wait_for(requests.get(), 3)
            finally:
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                release.set()
        adapter.teardown.assert_awaited_once()
        self.assertEqual(teardown_states, [True])
        self.assertTrue(all(child.returncode is not None for child in children))

    async def test_final_transfer_failure_never_returns_a_success_row(self):
        """Keep failed final AXFR/IXFR/export results out of all three runners' metrics."""
        adapter = SimpleNamespace(delete_zone=AsyncMock(), create_zone=AsyncMock(), import_records=AsyncMock(),
                                  xfr_endpoint=lambda: SimpleNamespace(host="127.0.0.1", port=1))
        error = dig.TransferError("bench.example", "127.0.0.1", 1, "AXFR", "incomplete")
        sampler = nullcontext()
        config = dict(sizes=[1], seed=1, ixfr_baseline=1, ixfr_change_sizes=[1])
        context = dict(zone="bench.example", label="test")
        with patch.object(dig, "zone_is_cleared", AsyncMock(return_value=True)), \
                patch.object(dig, "count_axfr_records", AsyncMock(return_value=3)), \
                patch.object(dig, "axfr", AsyncMock(side_effect=error)), \
                patch.object(dig, "ixfr", AsyncMock(side_effect=error)), \
                patch.object(b05_ixfr, "_query_serial", AsyncMock(side_effect=[1, 2, 2])), \
                patch.object(b04_axfr.asyncio, "sleep", AsyncMock()), \
                patch.object(b06_large_zone, "sampler_for", return_value=sampler):
            for module in (b04_axfr, b05_ixfr, b06_large_zone):
                with self.subTest(runner=module.__name__), self.assertRaises(dig.TransferError):
                    await module.run(adapter, config, context)
