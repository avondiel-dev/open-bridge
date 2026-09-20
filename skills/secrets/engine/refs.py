"""The reference grammar: one parser for every secret URI in the tree.

`rules/secret-placement.md` is the source of truth for WHICH schemes exist and
what each one addresses. This module is the machine-readable twin of that table,
and `scripts/check-secret-grammar.py` fails CI when the two drift apart, along
with the three other copies that had already drifted before this skill existed
(the overlay leak check, the workload engine, and the workload schema).

A reference is a locator, never a value. Parsing one is safe, printing one is
safe, and none of the functions here reaches a backend.

Grammar, per scheme:

    azure-keyvault://<vault>/<secret>
    keychain://<service>[/<account>]
    1password://<vault>/<item>/<field>
    op://<vault>/<item>/<field>                 alias of 1password, the CLI's own spelling
    keepass://<db>/<group>/.../<entry>/<field>
    vault://<mount>/<path>/.../<field>          HashiCorp Vault KV
    file://<absolute-path>                      a 0600 file inside a declared store

Two ways to name the field, because the slash form is ambiguous the moment an
entry is called "password": the last segment is the field, and `#field` at the
end overrides that and leaves every segment before it to the path.

    keepass://work/customers/acme/api-token#password
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from .errors import ReferenceError_


@dataclass(frozen=True)
class SchemeSpec:
    """What one scheme addresses, and what a well formed reference looks like."""

    name: str
    #: How many path segments the URI must carry, field included.
    min_segments: int
    max_segments: int | None
    #: True when the last segment is a field name rather than part of the path.
    has_field: str | None
    #: What the field is when the reference does not name one.
    default_field: str | None
    #: What the first segment means, for error messages and for `where`.
    store_noun: str
    summary: str


#: The declared schemes, in the order `rules/secret-placement.md` lists them.
#: `op` is an alias and is canonicalised away by `parse`, so it is not here.
SCHEMES: tuple[SchemeSpec, ...] = (
    SchemeSpec("azure-keyvault", 2, 2, None, None, "vault",
               "a secret in an Azure Key Vault"),
    SchemeSpec("keychain", 1, 2, None, None, "service",
               "a generic password item in an OS keychain"),
    SchemeSpec("1password", 2, None, "field", "password", "vault",
               "one field of one 1Password item"),
    SchemeSpec("keepass", 2, None, "field", "password", "database",
               "one field of one entry in a KeePass database"),
    SchemeSpec("vault", 2, None, "field", "value", "mount",
               "one field of one HashiCorp Vault KV secret"),
    SchemeSpec("file", 1, None, None, None, "path",
               "a file with mode 0600 inside a declared store"),
)

#: The CLI spelling that 1Password itself uses. Accepted on input, never emitted.
ALIASES = {"op": "1password"}

SCHEME_NAMES = tuple(spec.name for spec in SCHEMES)
BY_NAME = {spec.name: spec for spec in SCHEMES}

#: Every accepted spelling, aliases included. This is the tuple the overlay leak
#: check needs: a value that starts with one of these is a locator, so it is not
#: a raw secret and must not be reported as one.
URI_PREFIXES: tuple[str, ...] = tuple(
    f"{name}://" for name in sorted(set(SCHEME_NAMES) | set(ALIASES))
)

#: The workload schema and the workload engine both carry this pattern as a
#: literal, because that skill has to keep working when it is copied out of the
#: repo on its own. `scripts/check-secret-grammar.py` holds the three in sync.
ENV_VALUE_PATTERN_SOURCE = (
    r"^(" + "|".join(sorted(set(SCHEME_NAMES) | set(ALIASES))) + r")://\S+$"
)

#: Schemes this Bridge does NOT resolve, but which name a secret store all the
#: same. The scanner matches them so that `refs` and `check` can say "this is
#: written down and nothing here can read it", which is the `keeper://` case:
#: three occurrences in the account template, defined in no list, invisible to
#: every check because nothing ever looked for a scheme it did not already know.
#: A scheme outside both lists is not detected, and that limit is real: the
#: alternative is matching every `x://` in the tree, which means every URL.
FOREIGN_STORE_SCHEMES = (
    "keeper", "bitwarden", "lastpass", "dashlane", "doppler", "infisical",
    "gopass", "pass", "sops", "age", "akeyless", "cyberark", "thycotic",
    "secretsmanager", "secret-manager", "gsm", "credhub",
)

#: For finding references inside a file. Deliberately greedy about the tail and
#: trimmed afterwards, because a reference is usually quoted, and quoting styles
#: differ per file type.
REFERENCE_IN_TEXT = re.compile(
    r"\b(" + "|".join(sorted(set(SCHEME_NAMES) | set(ALIASES) | set(FOREIGN_STORE_SCHEMES)))
    + r")://[^\s\"'`,;<>\]\)}]+"
)

_TRAILING_JUNK = ".,;:)]}>"


@dataclass(frozen=True)
class Ref:
    """A parsed reference. `raw` is what the file actually said."""

    scheme: str
    store: str
    path: tuple[str, ...]
    field: str | None
    raw: str

    @property
    def spec(self) -> SchemeSpec:
        return BY_NAME[self.scheme]

    @property
    def canonical(self) -> str:
        """The reference as this skill spells it, aliases resolved.

        The slash form, because that is what `rules/secret-placement.md` writes
        and what people have in their files. It round trips: the field is the
        last segment on the way out and the last segment is read back as the
        field, even when the entry itself is called "password".
        """
        parts = [self.store, *self.path]
        if self.field is not None and self.spec.has_field:
            parts.append(self.field)
        if self.scheme == "file":
            return f"{self.scheme}://" + self.store
        return f"{self.scheme}://" + "/".join(_encode(part) for part in parts)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.canonical

    def label(self) -> str:
        """A short name for a column in a report."""
        tail = self.path[-1] if self.path else self.store
        return tail if self.field in (None, self.spec.default_field) else f"{tail}#{self.field}"


def describe_unparsed(uri) -> str:
    """What to say about something that is not a reference, without quoting it.

    A length and a fingerprint are enough to recognise which of two mistakes
    was made, and to compare a report with what was typed, and they disclose
    nothing. Used for operator input only: a string found in a tracked FILE is
    a locator by construction and is printed as it stands, because the point of
    that report is to say which line to go and fix.
    """
    import hashlib

    text = uri if isinstance(uri, str) else repr(type(uri).__name__)
    digest = hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()[:8]
    return f"<{len(text)} characters, sha256 {digest}>"


def _encode(segment: str) -> str:
    """Put back the three characters that would change the shape of the URI.

    `parse` decodes every segment, so a KeePass group actually named `team/sub`
    arrives as one segment. Joining the decoded segments with plain slashes
    turned it into two, and since `check` groups and deduplicates on the
    canonical form, the second read addressed a different entry while the
    docstring said the form round trips.
    """
    return segment.replace("%", "%25").replace("/", "%2F").replace("#", "%23")


def is_reference(text: str) -> bool:
    """True when `text` is spelled like a reference, whether or not it resolves."""
    return isinstance(text, str) and text.startswith(URI_PREFIXES)


def parse(uri: str) -> Ref:
    """Parse a reference, or raise `ReferenceError_` saying what is wrong with it.

    The error messages name the expected shape, because the caller is usually a
    person who has just written the URI by hand into a YAML file.
    """
    if not isinstance(uri, str) or "://" not in uri:
        # NOT `ref=uri`. The likeliest thing a person types where a reference
        # belongs is the value itself, the `docker run -e` habit:
        # `--env TOKEN=hunter2`. Echoing the argument back would put that value
        # in the error message, on stderr, in the transcript and in whatever
        # log the harness keeps, which is the one thing this skill exists to
        # prevent. So the message describes the input instead of quoting it.
        raise ReferenceError_(
            "not a secret reference",
            ref=describe_unparsed(uri),
            hint="expected <scheme>://…, one of: " + ", ".join(sorted(set(SCHEME_NAMES) | set(ALIASES))),
        )

    scheme, _, rest = uri.partition("://")
    scheme = scheme.strip().lower()
    scheme = ALIASES.get(scheme, scheme)
    if scheme not in BY_NAME:
        raise ReferenceError_(
            f"unknown scheme {scheme!r}",
            ref=uri,
            hint="rules/secret-placement.md lists the schemes this Bridge resolves",
        )
    spec = BY_NAME[scheme]

    hashed_field: str | None = None
    if "#" in rest:
        rest, hashed_field = rest.split("#", 1)
    if hashed_field is not None and not spec.has_field:
        raise ReferenceError_(
            f"{scheme}:// addresses {spec.summary}, which has no field",
            ref=uri,
            hint="drop the #field part",
        )

    if scheme == "file":
        # A file reference is a path, not a set of segments: it may contain
        # anything a filesystem allows, and splitting it would lose that.
        path = unquote(rest)
        if not path.startswith("/"):
            raise ReferenceError_(
                "file:// needs an absolute path",
                ref=uri,
                hint="file:///home/…/token, three slashes",
            )
        return Ref(scheme, path, (), None, uri)

    segments = [unquote(s) for s in rest.split("/") if s != ""]
    for segment in segments:
        # A percent-encoded newline survives `unquote` and, in the keychain
        # write path, would split the command line that goes to `security -i`
        # on stdin: everything after it becomes a SECOND command, with a name
        # the reference author chose. References arrive from YAML that an
        # overlay or a workload declaration supplies, so this is not only a
        # local typo. No store addresses anything with a control character in
        # it, so refusing costs nothing.
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in segment):
            raise ReferenceError_(
                "a control character in a reference",
                ref=describe_unparsed(uri),
                hint="a newline or a tab in a segment would end up in a command line",
            )
    if len(segments) < spec.min_segments:
        raise ReferenceError_(
            f"{scheme}:// needs at least {spec.min_segments} segments, got {len(segments)}",
            ref=uri,
            hint=_shape(spec),
        )
    if spec.max_segments is not None and len(segments) > spec.max_segments:
        raise ReferenceError_(
            f"{scheme}:// takes at most {spec.max_segments} segments, got {len(segments)}",
            ref=uri,
            hint=_shape(spec),
        )

    field = hashed_field
    if spec.has_field and field is None:
        if len(segments) > spec.min_segments:
            field = segments.pop()
        else:
            field = spec.default_field
    if field is not None and field.strip() == "":
        raise ReferenceError_("the field is empty", ref=uri, hint=_shape(spec))

    store, path = segments[0], tuple(segments[1:])
    if store.strip() == "":
        raise ReferenceError_(f"the {spec.store_noun} is empty", ref=uri, hint=_shape(spec))
    return Ref(scheme, store, path, field if spec.has_field else None, uri)


def _shape(spec: SchemeSpec) -> str:
    shapes = {
        "azure-keyvault": "azure-keyvault://<vault>/<secret>",
        "keychain": "keychain://<service>[/<account>]",
        "1password": "1password://<vault>/<item>/<field>",
        "keepass": "keepass://<db>/<group>/…/<entry>/<field>",
        "vault": "vault://<mount>/<path>/…/<field>",
        "file": "file://<absolute-path>",
    }
    return shapes[spec.name]


def iter_in_text(text: str):
    """Yield `(reference, follower)` for every reference spelled in `text`.

    `follower` is the character that stopped the match. It is what tells a
    reference apart from the first half of an example: `keepass://personal/`
    followed by `<` is somebody writing `keepass://personal/<org>/...` in prose,
    and the match stopped at the angle bracket because a real reference cannot
    contain one.
    """
    for match in REFERENCE_IN_TEXT.finditer(text):
        raw = match.group(0).rstrip(_TRAILING_JUNK)
        end = match.start() + len(raw)
        follower = text[end] if end < len(text) else ""
        yield raw, follower


def find_in_text(text: str) -> list[str]:
    """Every reference spelled inside a blob of text, in order of appearance.

    Used by `secrets refs` and by `secrets check --all`. It reads files that
    hold locators, never files that hold values, so nothing here is redacted.
    """
    return [raw for raw, _ in iter_in_text(text)]
