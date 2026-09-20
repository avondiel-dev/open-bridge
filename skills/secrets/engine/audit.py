"""`audit`: plaintext that should have been a reference, and where it belongs.

The direction the first two slices do not cover. `check` measures references
that exist; this one looks for the values that never became one. The finding
that started it: a maintainer copied another maintainer's instance to a second
machine and found small text files with tokens and credentials in working
folders and temp directories, because an agent handed a secret had nowhere
declared to put it and chose for itself.

Three things this module does that a plain grep does not.

**It knows what is declared.** A value inside a directory that a store declares
as a `file` store is not a finding, it is the store working. Reporting it would
train the reader to ignore the report, which is the failure mode of every
scanner that cries about its own fixtures.

**It says where the value belongs.** Each pattern carries the kind of secret it
usually is, and the kind resolves through the placement policy to a store and a
naming shape. A finding therefore reads "this is a GitHub token, it belongs in
X, call it Y" rather than "suspicious string".

**It reports PII and proposes nothing for it.** An IBAN in a tracked file is
worth knowing about and does not belong in a vault.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import discover, patterns as patterns_mod, stores as stores_mod

#: A finding here is not interesting: the file IS the declared store.
EXPECTED_IN_STORE = "inside a declared file store"


@dataclass
class Finding:
    """One hit, with its place and what to do about it."""

    path: str
    line: int
    pattern: str
    excerpt: str
    kind: str                    # credential | pii
    suggestion: str = ""
    store: str = ""
    expected: bool = False
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.path, "line": self.line, "pattern": self.pattern,
            "excerpt": self.excerpt, "kind": self.kind,
            "suggestion": self.suggestion, "store": self.store,
            "expected": self.expected, "note": self.note,
        }


@dataclass
class Report:
    findings: list = field(default_factory=list)
    files_read: int = 0
    skipped_binary: int = 0
    extra_roots: list = field(default_factory=list)
    #: Paths named with `--also` that are not there. A scan that cannot read
    #: what it was pointed at has to say so, or a typo reads as a clean tree.
    unreadable: list = field(default_factory=list)
    gitleaks: str = ""

    @property
    def credentials(self) -> list:
        return [f for f in self.findings if f.kind == "credential" and not f.expected]

    @property
    def pii(self) -> list:
        return [f for f in self.findings if f.kind == "pii" and not f.expected]

    @property
    def expected(self) -> list:
        return [f for f in self.findings if f.expected]


def declared_file_roots(stores) -> list:
    """Directories a `file` store declares, resolved."""
    roots = []
    for store in stores:
        if store.backend != "file":
            continue
        path = store.location.get("path")
        if path:
            roots.append(os.path.realpath(stores_mod.expand(path)))
    return roots


def run(root: str = ".", *, also=None, stores=None, include_pii: bool = True,
        runner=None) -> Report:
    """Scan the tree, and any extra path the caller names."""
    root = os.path.abspath(root)
    declared = stores if stores is not None else _load_quietly(root)
    roots = declared_file_roots(declared)
    report = Report(extra_roots=[os.path.abspath(p) for p in (also or [])])

    for base in [root, *report.extra_roots]:
        if base != root and not os.path.isdir(base):
            # `--also` names a PLACE, and the most useful place is often one
            # file: the stray `deploy.env` in a temp directory that this verb
            # exists for. `os.walk` over a non-directory yields nothing, so the
            # file was never read and the report said "clean", which a typo in
            # the path produced identically. Both now say what happened.
            if not os.path.exists(base):
                report.unreadable.append(base)
                continue
            names = [os.path.basename(base)]
            base = os.path.dirname(base) or "/"
        else:
            names = discover.candidate_files(base, runner=runner) if base == root \
                else discover._walked(base)
        for name in names:
            full = name if os.path.isabs(name) else os.path.join(base, name)
            if os.path.islink(full) or os.path.isdir(full):
                continue
            text = discover.readable_text(full)
            if text is None:
                report.skipped_binary += 1
                continue
            report.files_read += 1
            relative = os.path.relpath(full, base)
            inside = _inside(full, roots)
            for number, line in enumerate(text.splitlines(), 1):
                for pattern, excerpt in patterns_mod.scan_line(line, include_pii=include_pii):
                    report.findings.append(Finding(
                        path=relative if base == root else full,
                        line=number,
                        pattern=pattern.name,
                        excerpt=excerpt,
                        kind=pattern.kind,
                        expected=inside,
                        note=EXPECTED_IN_STORE if inside else pattern.note,
                    ))
    _suggest(report, declared)
    return report


def _load_quietly(root: str) -> list:
    try:
        return stores_mod.load(root)
    except stores_mod.MissingParser:
        return []


def _inside(path: str, roots) -> bool:
    real = os.path.realpath(path)
    return any(real == base or real.startswith(base.rstrip("/") + "/") for base in roots)


def _suggest(report: Report, stores) -> None:
    """Fill in where each credential belongs, from the placement policy."""
    cache: dict = {}
    for finding in report.findings:
        if finding.kind != "credential" or finding.expected:
            continue
        pattern = patterns_mod.BY_NAME.get(finding.pattern)
        kind = pattern.suggests if pattern else ""
        if not kind:
            continue
        if kind not in cache:
            try:
                cache[kind] = stores_mod.placements_for(stores, kind)
            except Exception:      # a kind the policy refuses is not a suggestion
                cache[kind] = []
        placements = cache[kind]
        if placements:
            placement = placements[0]
            finding.store = placement.store.name
            finding.suggestion = placement.reference_shape()
        else:
            finding.suggestion = f"declare a store that holds {kind}"


# ---------------------------------------------------------------------------
# the optional second opinion
# ---------------------------------------------------------------------------

def gitleaks_available(runner=None) -> bool:
    from . import exec as exec_mod

    return exec_mod.which("gitleaks") is not None


def gitleaks(root: str, *, runner=None) -> tuple[int, str]:
    """Run gitleaks over the tree when it is installed.

    A deliberate second opinion and not a replacement. The built-in set is small
    and readable and ships with the skill; gitleaks knows several hundred more
    shapes and is a static binary anybody can install. Neither proves the
    absence of a secret, and the report says that rather than implying it.
    """
    from . import exec as exec_mod

    if not gitleaks_available(runner=runner):
        return 0, "gitleaks is not installed here"
    done = exec_mod.run(["gitleaks", "dir", root, "--no-banner", "--report-format", "json",
                         "--report-path", "-"], runner=runner, timeout_sec=300)
    if done.rc not in (0, 1):
        return 0, f"gitleaks exited {done.rc}"
    try:
        parsed = json.loads(done.stdout or "[]")
    except json.JSONDecodeError:
        return 0, "gitleaks answered something that is not JSON"
    return len(parsed), f"gitleaks reported {len(parsed)} finding(s)"


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render(report: Report, *, verbose: bool = False) -> str:
    lines = []
    if report.credentials:
        lines.append("credentials in plain text:")
        for finding in report.credentials:
            lines.append(f"  {finding.path}:{finding.line}  {finding.pattern}  [{finding.excerpt}]")
            if finding.suggestion:
                where = f" in {finding.store}" if finding.store else ""
                lines.append(f"      belongs{where}: {finding.suggestion}")
            if finding.note and verbose:
                lines.append(f"      {finding.note}")
        lines.append("")
    if report.pii:
        lines.append("personal data, which is not a secret and is not moved:")
        for finding in report.pii:
            lines.append(f"  {finding.path}:{finding.line}  {finding.pattern}  [{finding.excerpt}]")
        lines.append("")
    if report.expected and verbose:
        lines.append(f"{len(report.expected)} hit(s) inside declared file stores, which is what a store is for")
        lines.append("")

    lines.append(f"{report.files_read} file(s) read, {len(report.credentials)} credential(s) to deal with, "
                 f"{len(report.pii)} personal-data hit(s)")
    for path in report.unreadable:
        lines.append(f"nothing at {path}, so it was not scanned")
    if report.gitleaks:
        lines.append(report.gitleaks)
    lines.append("A clean scan is not a proof: this reads the files it can, with the patterns it has.")
    return "\n".join(lines)
