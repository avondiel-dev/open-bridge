"""A directory as a store (docs/object-store.md, decision 2).

The rule that cost something elsewhere and must not cost it here: an unmounted
volume looks like a missing directory, and on Linux, or with a stale
/Volumes/<name> on macOS, it looks like an EMPTY directory. A backend that
wrote there would put the bytes on whatever disk holds the mount point, report
success, and leave the real volume without them.

So a local store is a directory that SAYS it is one: it carries a marker file,
`.object-store`, written once by `init` while the store is really there. The
marker travels with the volume. The mount point left behind by an unmounted
volume does not have it, and neither does a directory that was never a store.
The root itself is never created; `init` refuses a root that does not exist.

The root must be absolute (or start with `~`). A relative path resolves against
whatever directory the resolver happens to run in, which is usually the Bridge's
own work tree: the one place this whole family exists to keep content out of.

Every key is resolved and must stay inside the root after symlinks are
followed. The reference grammar already refuses `..`; this catches the link.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from ..errors import DeclarationError, NotFound, NotReachable, Refused
from .base import Stat, hash_file

MARKER = ".object-store"


class LocalBackend:
    def __init__(self, root):
        self.declared = str(root)
        self.root = Path(os.path.expanduser(self.declared))

    def _check_root(self) -> None:
        if not self.declared.strip() or not self.root.is_absolute():
            raise DeclarationError(
                f"a local store's path must be absolute or start with ~, not {self.declared!r}",
                hint="a relative path resolves against the current directory, usually the work tree")

    def probe(self) -> None:
        self._check_root()
        if not self.root.is_dir():
            raise NotReachable(
                f"the directory {self.root} is not there",
                hint="an unmounted volume looks exactly like this; nothing is created in its place")
        if not (self.root / MARKER).is_file():
            raise NotReachable(
                f"{self.root} exists but carries no {MARKER} marker",
                hint="the mount point of an unmounted volume looks exactly like this. When the store "
                     "really is there, mark it once with `object-store.sh init <store>`")

    def init(self) -> Path:
        """Mark an EXISTING directory as this store. Creates nothing else."""
        self._check_root()
        if not self.root.is_dir():
            raise NotReachable(f"the directory {self.root} is not there, so it cannot be marked",
                               hint="mount or create it first; init never creates a store's root")
        marker = self.root / MARKER
        if not marker.exists():
            marker.write_text("This directory is an object store root (docs/object-store.md).\n",
                              encoding="utf-8")
        return marker

    def _target(self, key: str) -> Path:
        self.probe()
        base = self.root.resolve()
        target = (base / key).resolve()
        if not target.is_relative_to(base):
            raise Refused(f"the key {key!r} resolves outside the store's root",
                          hint="a link inside the store points out of it")
        if target == base / MARKER:
            raise Refused(f"the key {key!r} is the store's own marker")
        return target

    def path(self, key: str) -> Path:
        target = self._target(key)
        if not target.is_file():
            raise NotFound(f"no object {key!r} in {self.root}")
        return target

    def stat(self, key: str) -> Stat:
        size, sha = hash_file(self.path(key))
        return Stat(size, sha)

    def fetch(self, key: str, dest) -> Stat:
        source = self.path(key)
        dest = Path(dest)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
        os.close(fd)
        try:
            shutil.copyfile(source, tmp)
            size, sha = hash_file(tmp)
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return Stat(size, sha)

    def put(self, key: str, source) -> Stat:
        target = self._target(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        os.close(fd)
        try:
            shutil.copyfile(source, tmp)
            size, sha = hash_file(tmp)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return Stat(size, sha)
