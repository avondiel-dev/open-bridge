"""The read cache: content addressed, capped, and honest about a hit."""

import os
import time

from tests.support import MARKER, FakeS3, Guarded, closed_port, mod, sha256


class ReadCache(Guarded):
    def resolver(self, root):
        return mod("objstore.resolver").Resolver(root=root, credentials=self.credentials())

    def test_a_second_read_is_served_from_the_cache_and_says_so(self):
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            resolver = self.resolver(root)
            resolver.put("object://exports/a.bin", source)
            first = resolver.path("object://exports/a.bin", expect_sha256=sha256(MARKER))
            second = resolver.path("object://exports/a.bin", expect_sha256=sha256(MARKER))
            gets = [r for r in fake.requests if r[0] == "GET"]
        self.assertEqual((first.source, second.source), ("store", "cache"))
        self.assertEqual(len(gets), 1)
        self.assertEqual(second.path.read_bytes(), MARKER)
        self.assertTrue(str(second.path).startswith(str(root / ".bridge" / "objects")))

    def test_an_offline_read_is_served_from_the_cache(self):
        root = self.bridge()
        cache = mod("objstore.cache").Cache(root / ".bridge" / "objects")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        cache.add(source, sha256(MARKER))
        self.declare_s3(root, "exports", f"http://127.0.0.1:{closed_port()}")
        with self.succeeds("a read of a cached object while its store is unreachable"):
            got = self.resolver(root).path("object://exports/a.bin", expect_sha256=sha256(MARKER))
        self.assertEqual(got.source, "cache")

    def test_content_that_does_not_match_its_hash_is_refused_and_not_cached(self):
        root = self.bridge()
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            resolver = self.resolver(root)
            resolver.put("object://exports/a.bin", source)
            with self.refuses(mod("objstore.errors").Refused):
                resolver.path("object://exports/a.bin", expect_sha256="0" * 64)
        cached = [p for p in (root / ".bridge" / "objects").rglob("*") if p.is_file()] \
            if (root / ".bridge" / "objects").exists() else []
        self.assertEqual(cached, [])

    def test_the_cache_stays_under_its_cap_by_dropping_the_oldest(self):
        cache = mod("objstore.cache").Cache(self.tmp / "cache", max_bytes=100)
        paths = []
        for index in range(3):
            source = self.tmp / f"in{index}.bin"
            source.write_bytes(bytes([index]) * 40)
            paths.append(cache.add(source, sha256(source.read_bytes())))
            old = time.time() - (10 - index)
            os.utime(paths[-1], (old, old))
        self.assertLessEqual(cache.size(), 100)
        self.assertFalse(paths[0].exists())
        self.assertTrue(paths[2].exists())

    def test_a_read_keeps_an_entry_young(self):
        """Least recently USED, not least recently written: reads touch."""
        cache = mod("objstore.cache").Cache(self.tmp / "cache", max_bytes=100)
        made = []
        for index, age in ((0, 30), (1, 20)):
            source = self.tmp / f"in{index}.bin"
            source.write_bytes(bytes([index]) * 40)
            made.append(cache.add(source, sha256(source.read_bytes())))
            old = time.time() - age
            os.utime(made[-1], (old, old))
        cache.get(sha256(bytes([0]) * 40))          # the older one is read
        third = self.tmp / "in2.bin"
        third.write_bytes(bytes([2]) * 40)
        cache.add(third, sha256(third.read_bytes()))
        self.assertTrue(made[0].exists(), "the entry that was just read was evicted")
        self.assertFalse(made[1].exists())

    def test_a_cached_file_is_read_only(self):
        """`path` hands out the cache file itself. A caller that edits it in
        place would otherwise change what every later hit serves under the
        same hash."""
        cache = mod("objstore.cache").Cache(self.tmp / "cache")
        source = self.tmp / "in.bin"
        source.write_bytes(MARKER)
        got = cache.add(source, sha256(MARKER))
        self.assertEqual(got.stat().st_mode & 0o222, 0)

    def test_an_object_too_large_for_the_cache_is_refused_before_it_is_downloaded(self):
        root = self.bridge()
        source = self.tmp / "big.bin"
        source.write_bytes(MARKER * 10)
        with FakeS3() as fake:
            self.declare_s3(root, "exports", fake.endpoint)
            resolver = mod("objstore.resolver").Resolver(
                root=root, credentials=self.credentials(),
                cache=mod("objstore.cache").Cache(root / ".bridge" / "objects", max_bytes=10))
            resolver.put("object://exports/big.bin", source)
            with self.refuses(mod("objstore.errors").Refused):
                resolver.path("object://exports/big.bin")
            self.assertNotIn("GET", [method for method, _ in fake.requests])

    def test_an_object_larger_than_the_cap_is_not_cached(self):
        cache = mod("objstore.cache").Cache(self.tmp / "cache", max_bytes=10)
        source = self.tmp / "big.bin"
        source.write_bytes(b"x" * 11)
        self.assertIsNone(cache.add(source, sha256(source.read_bytes())))
        self.assertEqual(cache.size(), 0)
