"""The read cache under .bridge/objects/: content addressed, capped, honest.

A file is stored under its sha256, so a hit is a hit on the bytes and never on a
name that has since pointed at something else. `.bridge/` is ignored by the
shipped .gitignore, so nothing here can reach a commit.

Cached files are READ-ONLY. `path` hands out the cache file itself, and a
caller that edited it in place would change what every later hit serves under
the same hash.

The cap is enforced on every add by dropping the least recently USED files
(reads touch the file), and an object larger than the whole cap is not cached
at all. A temporary `.incoming-*` file left by a killed run is removed once it
is an hour old.

The cache keeps a copy after the store has deleted the object, for as long as
somebody knows its hash. When an object has to be ERASED (special-category data
under an erasure request), `forget` removes it here too.

This is a READ cache only. Nothing is ever written here on the way to a store:
a write that cannot land fails (docs/object-store.md, decision 5).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path

from .errors import UsageError

DEFAULT_MAX_BYTES = 2 * 1024 ** 3
ENV_MAX = "OBJECT_STORE_CACHE_MAX_BYTES"
STALE_INCOMING_SECONDS = 3600
_SHA = re.compile(r"^[0-9a-f]{64}$")
_READ_ONLY = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH


def normalise_sha256(value: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.match(text):
        raise UsageError(f"{value!r} is not a sha256: 64 hexadecimal characters are expected")
    return text


class Cache:
    def __init__(self, directory, max_bytes: int | None = None):
        self.directory = Path(directory)
        if max_bytes is None:
            raw = os.environ.get(ENV_MAX, str(DEFAULT_MAX_BYTES))
            try:
                max_bytes = int(raw)
            except ValueError:
                raise UsageError(f"{ENV_MAX} is {raw!r}, a number of bytes is expected") from None
        self.max_bytes = max_bytes

    def _path(self, sha256: str) -> Path:
        sha = normalise_sha256(sha256)
        return self.directory / sha[:2] / sha

    def get(self, sha256: str) -> Path | None:
        path = self._path(sha256)
        if not path.is_file():
            return None
        try:
            os.utime(path)
        except OSError:
            pass
        return path

    def forget(self, sha256: str) -> bool:
        path = self._path(sha256)
        if not path.is_file():
            return False
        path.unlink()
        return True

    def add(self, source, sha256: str, *, move: bool = False) -> Path | None:
        """Store `source` under its hash. The caller has verified the hash."""
        source = Path(source)
        size = source.stat().st_size
        if size > self.max_bytes:
            return None
        target = self._path(sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        if move:
            os.replace(source, target)
        else:
            fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".incoming-")
            os.close(fd)
            try:
                shutil.copyfile(source, tmp)
                os.replace(tmp, target)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        os.chmod(target, _READ_ONLY)
        self._evict(keep=target)
        return target if target.exists() else None

    def files(self) -> list:
        if not self.directory.is_dir():
            return []
        return [p for p in self.directory.rglob("*") if p.is_file() and not p.name.startswith(".")]

    def size(self) -> int:
        return sum(p.stat().st_size for p in self.files())

    def _drop_stale_incoming(self) -> None:
        cutoff = time.time() - STALE_INCOMING_SECONDS
        for path in self.directory.rglob(".incoming-*"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except FileNotFoundError:
                pass

    def _evict(self, keep: Path) -> None:
        self._drop_stale_incoming()
        entries = []
        for path in self.files():
            try:
                info = path.stat()
            except FileNotFoundError:   # another run evicted it first
                continue
            entries.append((info.st_mtime, info.st_size, path))
        entries.sort(key=lambda entry: entry[0])
        total = sum(size for _, size, _ in entries)
        for _, size, path in entries:
            if total <= self.max_bytes:
                break
            if path == keep:
                continue
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            total -= size
