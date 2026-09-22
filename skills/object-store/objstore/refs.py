"""The object reference grammar: object://<store>/<key>.

This module carries a COPY of the grammar. The source is
infra/object-stores/_schema.yaml (the `name` pattern, the `backend` enum and
`$defs/reference`), and scripts/check-object-grammar.py fails CI the day this
copy stops answering like it: it feeds a fixed list of sample references to the
schema's pattern and to `parse` below, and every answer has to match. The
literals are copies rather than a read of the schema on purpose: the skill has
to keep working when its directory is lifted out of the repo on its own.

The key is opaque to everything but the store, with the rules that are about
safety rather than about the store: no empty segment, no `.` or `..` segment,
no backslash, no whitespace. A key that can climb out of its store's root is a
path traversal waiting for a local backend to follow it. The schema's pattern
carries the same rules, so a reference that validates also resolves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import MalformedReference

SCHEME = "object"
STORE_PATTERN = "[a-z][a-z0-9-]*"
BACKENDS = ("local", "s3")
#: One key segment: not `.` or `..`, no slash, whitespace or backslash.
SEGMENT = r"(?!\.\.?(?:/|$))[^/\s\\]+"
KEY_PATTERN = SEGMENT + r"(?:/" + SEGMENT + r")*"

_prefix = "^" + SCHEME + "://"
_SHAPE = re.compile(_prefix + r"(" + STORE_PATTERN + r")/(\S*)$")
_REFERENCE = re.compile(_prefix + r"(" + STORE_PATTERN + r")/(" + KEY_PATTERN + r")$")


@dataclass(frozen=True)
class ObjectRef:
    store: str
    key: str

    @property
    def canonical(self) -> str:
        return f"{SCHEME}://{self.store}/{self.key}"


def parse(uri: str) -> ObjectRef:
    text = str(uri).strip()
    if _SHAPE.match(text) is None:
        raise MalformedReference(
            "not an object reference",
            ref=text,
            hint="expected object://<store>/<key>; a backend URI such as s3://bucket/key "
                 "names a location, not a declared store (docs/object-store.md, decision 3)")
    match = _REFERENCE.match(text)
    if match is None:
        raise MalformedReference(
            "the key is empty, or has an empty, '.' or '..' segment, or a backslash",
            ref=text, hint="a key may not climb out of its store or start at a root")
    return ObjectRef(store=match.group(1), key=match.group(2))
