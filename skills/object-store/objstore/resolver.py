"""One resolver every caller goes through (docs/object-store.md, decision 6).

It hands out a path, never content. `path` returns a filesystem path to the
object's bytes: the object itself for a local store, the cache copy for a remote
one. `fetch` writes the bytes to a file the caller names. `stat` returns size
and hash. Nothing here returns the bytes as a value, because a multi-gigabyte
object would end the session that asked for it.

Reads consult the cache first when the caller knows the content hash, which a
tracked entry does, and only then the store. That is also the offline answer:
a store that cannot be reached still serves what was read before, and says it
came from the cache. Writes never touch the cache and never queue.

A miss that is a reachability problem names where the declaration says the
store is reachable from. The resolver never decides reachability from that
field, it measures; the field only explains the measurement.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import credentials as credentials_mod
from . import refs as refs_mod
from . import stores as stores_mod
from .backends.local import LocalBackend
from .backends.s3 import S3Backend
from .cache import Cache, normalise_sha256
from .errors import NotReachable, Refused, UndeclaredStore, UsageError

CACHE_DIR = (".bridge", "objects")


@dataclass(frozen=True)
class Result:
    uri: str
    size: int | None
    sha256: str | None
    source: str                 # "store" or "cache"
    path: Path | None = None


class Resolver:
    def __init__(self, root=".", *, stores=None, cache: Cache | None = None,
                 credentials=None, timeout: float = 30):
        self.root = Path(root)
        self._stores = stores
        self.cache = cache or Cache(self.root.joinpath(*CACHE_DIR))
        self.credentials = credentials
        self.timeout = timeout

    # -- declarations -------------------------------------------------------

    @property
    def stores(self) -> list:
        if self._stores is None:
            self._stores = stores_mod.load(self.root)
        return self._stores

    def locate(self, uri: str):
        ref = refs_mod.parse(uri)
        store = stores_mod.for_reference(self.stores, ref)
        if store is None:
            raise UndeclaredStore(
                f"no declaration in infra/object-stores/ answers the store {ref.store!r}",
                ref=ref.canonical,
                hint="the reference is well formed; this instance does not know that store")
        return ref, store

    def named(self, name: str):
        for store in self.stores:
            if store.name == name:
                return store
        raise UndeclaredStore(f"no declaration in infra/object-stores/ is named {name!r}")

    def backend(self, store):
        if store.backend == "local":
            return LocalBackend(store.location.get("path", ""))
        access, secret = credentials_mod.keys_for(store, self.credentials, self.root)
        return S3Backend(
            endpoint=str(store.location.get("endpoint", "")),
            bucket=str(store.location.get("bucket", "")),
            region=str(store.location.get("region") or "us-east-1"),
            prefix=str(store.location.get("prefix") or ""),
            access_key=access, secret_key=secret, timeout=self.timeout)

    @contextlib.contextmanager
    def _explained(self, store):
        try:
            yield
        except NotReachable as exc:
            declared = store.reachable_from or {}
            machines = ", ".join(str(m) for m in declared.get("machines") or []) or "this machine only"
            contexts = ", ".join(str(c) for c in declared.get("contexts") or []) or "unstated"
            note = f"declared reachable from: {machines} (contexts: {contexts}), per {store.source}"
            exc.hint = f"{exc.hint}\n  {note}" if exc.hint else note
            raise

    # -- reads --------------------------------------------------------------

    def stat(self, uri: str) -> Result:
        ref, store = self.locate(uri)
        with self._explained(store):
            stat = self.backend(store).stat(ref.key)
        return Result(ref.canonical, stat.size, stat.sha256, "store")

    def _hit(self, ref, expect_sha256):
        if not expect_sha256:
            return None
        hit = self.cache.get(expect_sha256)
        if hit is None:
            return None
        return Result(ref.canonical, hit.stat().st_size, expect_sha256, "cache", hit)

    @staticmethod
    def _verify(ref, got: str | None, expect: str | None) -> None:
        if expect and got != expect:
            raise Refused("the content does not match the hash the entry tracks",
                          ref=ref.canonical,
                          hint=f"expected sha256 {expect[:12]}, the store holds {str(got)[:12]}")

    def path(self, uri: str, *, expect_sha256: str | None = None) -> Result:
        expect = normalise_sha256(expect_sha256) if expect_sha256 else None
        ref, store = self.locate(uri)
        hit = self._hit(ref, expect)
        if hit is not None:
            return hit
        with self._explained(store):
            backend = self.backend(store)
            if store.backend == "local":
                found = backend.path(ref.key)
                if not expect:
                    return Result(ref.canonical, found.stat().st_size, None, "store", found)
                stat = backend.stat(ref.key)
                self._verify(ref, stat.sha256, expect)
                return Result(ref.canonical, stat.size, stat.sha256, "store", found)
            head = backend.stat(ref.key)
            if head.size is not None and head.size > self.cache.max_bytes:
                raise Refused(f"the object is {head.size} bytes, larger than the cache cap of "
                              f"{self.cache.max_bytes}", ref=ref.canonical,
                              hint="use `fetch --to <file>` for an object this size")
            self.cache.directory.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.cache.directory, prefix=".incoming-")
            os.close(fd)
            try:
                stat = backend.fetch(ref.key, tmp)
                self._verify(ref, stat.sha256, expect)
                cached = self.cache.add(tmp, stat.sha256, move=True)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        if cached is None:
            raise Refused(f"the object is {stat.size} bytes, larger than the cache cap",
                          ref=ref.canonical, hint="use `fetch --to <file>` for an object this size")
        return Result(ref.canonical, stat.size, stat.sha256, "store", cached)

    def fetch(self, uri: str, dest, *, expect_sha256: str | None = None) -> Result:
        expect = normalise_sha256(expect_sha256) if expect_sha256 else None
        dest = Path(dest)
        if not dest.parent.is_dir():
            raise UsageError(f"the directory for {dest} does not exist")
        ref, store = self.locate(uri)
        hit = self._hit(ref, expect)
        if hit is not None:
            shutil.copyfile(hit.path, dest)
            return Result(ref.canonical, hit.size, hit.sha256, "cache", dest)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
        os.close(fd)
        try:
            with self._explained(store):
                stat = self.backend(store).fetch(ref.key, tmp)
            self._verify(ref, stat.sha256, expect)
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        if store.backend != "local":
            self.cache.add(dest, stat.sha256)
        return Result(ref.canonical, stat.size, stat.sha256, "store", dest)

    # -- writes -------------------------------------------------------------

    def put(self, uri: str, source) -> Result:
        """Write to the store or fail. There is no second place a write can go."""
        source = Path(source)
        if not source.is_file():
            raise UsageError(f"{source} is not a file")
        ref, store = self.locate(uri)
        with self._explained(store):
            stat = self.backend(store).put(ref.key, source)
        return Result(ref.canonical, stat.size, stat.sha256, "store")

    def init(self, name: str) -> Path:
        store = self.named(name)
        if store.backend != "local":
            raise UsageError(f"{name} is a {store.backend} store; only a local store carries a marker")
        with self._explained(store):
            return self.backend(store).init()

    def forget(self, sha256: str) -> bool:
        return self.cache.forget(normalise_sha256(sha256))
