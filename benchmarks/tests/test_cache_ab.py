"""The cache A/B setup must use role-based, zone-scoped transfer credentials."""
from contextlib import asynccontextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ab.zone_cache_ab import create_transfer_key


class CacheAbTests(IsolatedAsyncioTestCase):
    async def test_transfer_key_uses_a_role_granted_only_the_requested_zone(self):
        """Create a key with only the requested zone's transfer grant."""
        requests = []

        class Response:
            status = 201

            async def json(self):
                """Return a created TSIG key and secret."""
                return {"tsig_key": {"name": "bench-axfr", "algorithm": "hmac-sha256"},
                        "secret": "c2VjcmV0"}

        @asynccontextmanager
        async def post(url, *, json):
            """Capture the outgoing management request."""
            requests.append((url, json))
            yield Response()

        adapter = SimpleNamespace(base="http://unit", session=SimpleNamespace(post=post))
        key = await create_transfer_key(adapter, "bench.example.")
        self.assertEqual(key, "hmac-sha256:bench-axfr:c2VjcmV0")
        self.assertEqual(requests, [
            ("http://unit/roles", {"name": "bench-axfr"}),
            ("http://unit/roles/bench-axfr/grants",
             {"zone_name": "bench.example", "actions": ["zone:transfer"]}),
            ("http://unit/tsig-keys", {"name": "bench-axfr", "role_name": "bench-axfr"}),
        ])

    async def test_failed_role_setup_cannot_continue_to_key_creation(self):
        """A denied role creation must stop key setup."""
        requests = []

        class Response:
            status = 403

            async def text(self):
                """Return the role denial."""
                return "forbidden"

        @asynccontextmanager
        async def post(url, *, json):
            """Return a forbidden role response and capture the request."""
            requests.append(url)
            yield Response()

        adapter = SimpleNamespace(base="http://unit", session=SimpleNamespace(post=post))
        with self.assertRaisesRegex(RuntimeError, "creating the transfer role failed"):
            await create_transfer_key(adapter, "bench.example")
        self.assertEqual(requests, ["http://unit/roles"])
