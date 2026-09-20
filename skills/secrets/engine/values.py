"""The value itself, wrapped so that printing it takes an explicit act.

Three things live here.

`Secret` holds the bytes. Its `repr` is a description, its `str` raises, and the
only way to the content is `expose()`, a verb chosen so that `grep -rn expose(`
lists every place in this skill where a value leaves its wrapper. That is the
review surface; a plain `str` would have none.

`fingerprint` is how two machines compare a secret without either of them
learning the other's copy: the first eight hex characters of its sha256. Long
enough to tell two live tokens apart in a report, short enough that it is not a
useful handle for an attacker who has the report but not the vault.

`Redactor` removes values from text that a child process produced, before that
text reaches the agent. It redacts the encodings a value plausibly wears on the
way out (base64, hex, percent escapes, JSON escapes), because a token that was
posted to an API and echoed back inside a JSON error message is not spelled the
way it was stored.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from urllib.parse import quote

#: A value shorter than this is not redacted: the replacement would fire on
#: ordinary words and hide the very output the caller needs to read. The run
#: reports which names were skipped rather than pretending they were covered.
MIN_REDACTABLE = 6

#: What a redacted stretch is replaced with. It names the variable, so a reader
#: of the output can tell which secret was involved without seeing it.
def placeholder(name: str) -> str:
    return f"[redacted:{name}]"


class Secret:
    """Bytes that must not be printed by accident."""

    __slots__ = ("_value", "origin")

    def __init__(self, value: bytes | str, *, origin: str = ""):
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            # `bytes(5)` is five zero bytes and `bytes(True)` is one. A value
            # that arrived as a number (a YAML `password: 12345678` parses as an
            # int) would become that many NUL bytes: not empty, with a
            # fingerprint, reported as a healthy read all the way up.
            raise TypeError(
                f"a Secret holds text or bytes, not {type(value).__name__}. "
                f"Decode it where it is read, so the conversion is visible."
            )
        self._value = bytes(value)
        #: Where it came from, as a reference string. Safe to print.
        self.origin = origin

    # -- description, never content ----------------------------------------

    def __repr__(self) -> str:
        return f"<Secret {self.origin or 'anonymous'} bytes={len(self)} fp={self.fingerprint}>"

    def __str__(self) -> str:
        raise TypeError(
            "a Secret does not render as text. Use .expose() where the value is "
            "actually needed, or .describe() for a report."
        )

    def __format__(self, spec: str) -> str:  # pragma: no cover - same rule as __str__
        raise TypeError("a Secret does not format as text; use .describe()")

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:  # pragma: no cover - identity of the wrapper only
        return hash(self.fingerprint)

    # -- the two accessors --------------------------------------------------

    def expose(self) -> bytes:
        """The value. Every call site of this is a place a secret can leak."""
        return self._value

    def expose_text(self) -> str:
        """The value as text, for tools that speak strings."""
        return self._value.decode("utf-8", errors="surrogateescape")

    # -- description --------------------------------------------------------

    @property
    def fingerprint(self) -> str:
        """First eight hex characters of the sha256 of the value."""
        return hashlib.sha256(self._value).hexdigest()[:8]

    def describe(self) -> str:
        return f"{len(self)} bytes, sha256 {self.fingerprint}"

    def is_empty(self) -> bool:
        """An entry with no bytes in it. A hit for the store, a miss for the caller."""
        return len(self._value) == 0


def fingerprint(value: bytes | str) -> str:
    """Fingerprint of a raw value, for code that has not wrapped it yet."""
    return Secret(value).fingerprint


class Redactor:
    """Removes registered values, and their common encodings, from text."""

    def __init__(self, min_length: int = MIN_REDACTABLE):
        self.min_length = min_length
        #: (variant, name), sorted longest first when the patterns are built.
        self._registered: list[tuple[str, str]] = []
        self._compiled: list[tuple[re.Pattern[str], str]] | None = None
        #: Names whose value was too short to redact safely.
        self.skipped: list[str] = []
        self._names: list[str] = []

    def register(self, name: str, secret: Secret) -> None:
        if len(secret) < self.min_length:
            self.skipped.append(name)
            return
        self._names.append(name)
        for variant in self._variants(secret):
            if len(variant) < self.min_length:
                continue
            self._registered.append((variant, name))
        self._compiled = None

    @property
    def _patterns(self) -> list[tuple[re.Pattern[str], str]]:
        """Longest variant first, across every registered secret.

        Sorting within one registration is not enough: with two secrets where
        one value starts with the other, the shorter one registered first was
        substituted inside the longer one and the tail of the longer value
        survived. `holds` then called the residue clean and the stream was
        printed. Two references in the order somebody typed them is all it took.
        """
        if self._compiled is None:
            ordered = sorted(self._registered, key=lambda pair: len(pair[0]), reverse=True)
            self._compiled = [(re.compile(re.escape(variant)), placeholder(name))
                              for variant, name in ordered]
        return self._compiled

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._names)

    def _variants(self, secret: Secret) -> set[str]:
        raw = secret.expose()
        out: set[str] = set()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text:
            out.add(text)
            out.add(text.strip())
            out.add(quote(text, safe=""))
            out.add(json.dumps(text)[1:-1])
        # `printenv TOKEN | base64` encodes the value WITH the newline the shell
        # added, and that encoding shares only a prefix with the encoding of the
        # value alone. Measured: one character of the real base64 survived the
        # scrub. So the line endings a value picks up on the way out are
        # registered as variants of their own.
        for payload in (raw, raw + b"\n", raw + b"\r\n"):
            for encoder in (base64.b64encode, base64.urlsafe_b64encode):
                encoded = encoder(payload).decode("ascii")
                out.add(encoded)
                out.add(encoded.rstrip("="))
        hexed = binascii.hexlify(raw).decode("ascii")
        out.add(hexed)
        out.add(hexed.upper())
        return {v for v in out if v}

    def scrub(self, text: str) -> str:
        """Replace every registered value with its placeholder."""
        if not text:
            return text
        for pattern, replacement in self._patterns:
            text = pattern.sub(replacement, text)
        return text

    def holds(self, text: str) -> bool:
        """True when the text still contains a registered value.

        The assertion a test makes after scrubbing. In production it is the
        second pair of eyes: `run` calls it on its own output and refuses to
        print anything it could not clean.
        """
        return any(pattern.search(text) for pattern, _ in self._patterns)


@dataclass(frozen=True)
class Reading:
    """What a backend returns: the value, plus where it came from.

    Kept separate from `Secret` so a report can carry the metadata of a read
    that never happened (`present=False`) without carrying an empty Secret that
    a careless caller might inject as if it were real.
    """

    ref: str
    present: bool
    secret: Secret | None = None
    store: str = ""
    note: str = ""

    @property
    def length(self) -> int:
        return len(self.secret) if self.secret is not None else 0

    @property
    def fingerprint(self) -> str:
        return self.secret.fingerprint if self.secret is not None else ""
