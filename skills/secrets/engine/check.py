"""`check`: does every reference in the tree still point at something.

The measurement is the value, not the entry. `security find-generic-password`
exits 0 for an item that holds zero bytes, and a check that tested existence
reported green while the caller got an empty string and failed one layer later,
where it looked like a permission problem. So a row is green only when bytes
came back, and the report carries the length and the fingerprint as the evidence
that something was actually read.

The second column nobody had is CONTEXT. The same reference is readable from a
desktop session and refused over ssh. A report that says "ok" on the laptop and
"missing" on the same laptop over ssh is not measuring the vault, it is
measuring the session, and it has to say which.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import discover, refs as refs_mod
from .errors import SecretsError
from .resolve import Resolver

#: The verdicts, worst last. `check` exits non zero from BAD_REFERENCE onwards.
OK = "ok"
EMPTY = "empty"
MISSING = "missing"
UNREADABLE = "not readable here"
NO_BACKEND = "no backend here"
BAD_REFERENCE = "bad reference"
ERROR = "error"

FAILING = (EMPTY, MISSING, BAD_REFERENCE, ERROR)


@dataclass
class Row:
    """One reference, measured."""

    ref: str
    scheme: str = ""
    status: str = OK
    where: str = ""
    length: int = 0
    fingerprint: str = ""
    note: str = ""
    places: list = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.status in FAILING

    def as_dict(self) -> dict:
        return {
            "ref": self.ref,
            "scheme": self.scheme,
            "status": self.status,
            "where": self.where,
            "bytes": self.length,
            "fingerprint": self.fingerprint,
            "note": self.note,
            "places": list(self.places),
        }


def check_refs(resolver: Resolver, references, places=None) -> list[Row]:
    """Measure each reference. `places` maps a reference to where it is written."""
    places = places or {}
    rows = []
    for reference in references:
        rows.append(check_one(resolver, reference, places.get(_key(reference), [])))
    return rows


def _key(reference) -> str:
    return reference.canonical if isinstance(reference, refs_mod.Ref) else str(reference)


def check_one(resolver: Resolver, reference, places=None) -> Row:
    places = list(places or [])
    try:
        parsed = reference if isinstance(reference, refs_mod.Ref) else refs_mod.parse(str(reference))
    except SecretsError as problem:
        return Row(ref=str(reference), status=BAD_REFERENCE, note=str(problem), places=places)

    row = Row(ref=parsed.canonical, scheme=parsed.scheme, places=places)
    try:
        readable, why = resolver.readable_here(parsed)
        row.where = resolver.locate(parsed)
        if not readable:
            row.status = UNREADABLE if resolver.backend(parsed.scheme).available() else NO_BACKEND
            row.note = why
            return row
        reading = resolver.read(parsed)
    except SecretsError as problem:
        row.status = _status_for(problem)
        row.note = problem.hint or str(problem)
        if not row.where:
            row.where = ""
        return row

    row.note = reading.note
    if reading.present and reading.secret is not None:
        row.status = OK
        row.length = len(reading.secret)
        row.fingerprint = reading.secret.fingerprint
    elif reading.secret is not None and reading.secret.is_empty():
        row.status = EMPTY
    else:
        row.status = MISSING
    return row


def _status_for(problem: SecretsError) -> str:
    from .errors import BackendUnavailable, NotReadableHere, ReferenceError_, SecretMissing

    if isinstance(problem, NotReadableHere):
        return UNREADABLE
    if isinstance(problem, BackendUnavailable):
        return NO_BACKEND
    if isinstance(problem, SecretMissing):
        return MISSING
    if isinstance(problem, ReferenceError_):
        return BAD_REFERENCE
    return ERROR


def check_tree(resolver: Resolver, root: str, *, runner=None) -> tuple[list[Row], list]:
    """Every reference written down in the tree, measured once each."""
    findings = discover.find(root, runner=runner)
    grouped = discover.group_by_ref(findings, examples=False)
    places = {
        key: [f"{f.path}:{f.line}" for f in group]
        for key, group in grouped.items()
    }
    rows = check_refs(resolver, discover.unique_refs(findings), places)
    # An example in prose is not a broken reference. A reference that means to
    # be real and does not parse is, and that is the row worth having. One row
    # per REFERENCE, not per occurrence: a single typo written in two files was
    # two rows, each naming only its own place, and the tally then counted one
    # mistake twice.
    broken: dict = {}
    for finding in findings:
        if finding.ok or finding.example:
            continue
        entry = broken.setdefault(finding.raw, {"error": finding.error, "places": []})
        entry["places"].append(f"{finding.path}:{finding.line}")
    for raw, entry in broken.items():
        rows.append(Row(ref=raw, status=BAD_REFERENCE, note=entry["error"],
                        places=entry["places"]))
    return rows, findings


def render(rows, *, verbose: bool = False) -> str:
    """A table. Names, lengths, fingerprints; never a value."""
    if not rows:
        return "no references found"
    head = ("reference", "status", "bytes", "sha256", "where")
    body = [
        (row.ref, row.status, str(row.length or ""), row.fingerprint, row.where or row.note)
        for row in rows
    ]
    widths = [max(len(head[i]), *(len(line[i]) for line in body)) for i in range(len(head))]
    lines = ["  ".join(head[i].ljust(widths[i]) for i in range(len(head))).rstrip()]
    lines.append("  ".join("-" * widths[i] for i in range(len(head))))
    for row, line in zip(rows, body):
        lines.append("  ".join(line[i].ljust(widths[i]) for i in range(len(head))).rstrip())
        if row.note and (verbose or row.failed) and row.note != line[4]:
            lines.append(f"    {row.note}")
        if verbose and row.places:
            lines.append("    " + ", ".join(row.places))
    # The tally counts what each row actually says. Deriving "resolved" as
    # everything that did not fail counted a row nothing could read as resolved,
    # so the summary contradicted the line above it.
    resolved = [row for row in rows if row.status == OK]
    failed = [row for row in rows if row.failed]
    unread = [row for row in rows if row.status in (UNREADABLE, NO_BACKEND)]
    lines.append("")
    summary = f"{len(rows)} references, {len(resolved)} resolved, {len(failed)} to look at"
    if unread:
        summary += f", {len(unread)} not readable from this session"
    lines.append(summary)
    return "\n".join(lines)
