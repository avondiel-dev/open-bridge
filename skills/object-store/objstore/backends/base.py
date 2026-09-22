"""What every backend answers, and the one helper they share."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Stat:
    size: int
    sha256: str | None


def hash_file(path) -> tuple:
    """Size and sha256 of a file, read in chunks so a large object never sits in memory."""
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()
