"""Where the references are. An inventory, derived, never a second list.

The alternative would be a registry file naming every secret the Bridge uses. It
would be wrong within a week, and wrong in the direction that matters: a
reference nobody registered is exactly the one nobody checks. So the inventory
is derived from the tree, and whatever a file actually says is what `check`
measures.

This module reads files that hold LOCATORS. It never opens a vault and never
holds a value, so nothing here needs redacting.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from . import refs as refs_mod
from .errors import ReferenceError_

#: Directories that hold no declaration and cost the most to walk.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache",
             ".pytest_cache", "dist", "build", ".bridge"}

#: Anything larger is not a declaration.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: What a written-out EXAMPLE looks like. Documentation is full of references
#: with a placeholder in them (`keychain://<service>/<account>`), and a scan
#: that reported those as broken would drown the real ones: measured on this
#: repo, 19 of 38 hits are examples in prose.
PLACEHOLDER_MARKS = ("<", ">", "{", "}", "$", "\u2026", "...", "%s")


@dataclass(frozen=True)
class Finding:
    """One reference, where it stands."""

    path: str
    line: int
    raw: str
    ref: object | None = None      # refs.Ref when it parses
    error: str = ""
    example: bool = False          # a reference with a placeholder in it, in prose

    @property
    def ok(self) -> bool:
        return self.ref is not None


def candidate_files(root: str, *, runner=None) -> list[str]:
    """Files to search, tracked ones first.

    In a git tree the tracked set is the right one: it is what ships, and it
    leaves out the working files a scan would otherwise drown in. Outside a git
    tree, or when git is not there, the walk is the fallback and says so by
    simply returning everything it can read.
    """
    listed = _git_tracked(root, runner=runner)
    if listed is not None:
        return listed
    return _walked(root)


def _git_tracked(root: str, *, runner=None) -> list[str] | None:
    from . import exec as exec_mod

    done = exec_mod.run(["git", "-C", root, "ls-files", "-z"], runner=runner)
    if done.rc != 0 or not done.stdout:
        return None
    return [name for name in done.stdout.split("\0") if name]


def _walked(root: str) -> list[str]:
    out = []
    for base, dirs, files in os.walk(root):
        # `.git` is in SKIP_DIRS already. A prefix test on top of it also
        # pruned `.github`, which is where a workflow names a Key Vault secret,
        # so the same tree scanned with and without git disagreed about its own
        # inventory.
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = os.path.join(base, name)
            out.append(os.path.relpath(full, root))
    return sorted(out)


def readable_text(path: str) -> str | None:
    """The text of a file, or None when it is binary, huge or unreadable."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    if b"\0" in blob[:4096]:
        return None
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return None


def find(root: str, paths=None, *, runner=None, base: str | None = None) -> list[Finding]:
    """Every reference in the tree, or in the paths given.

    A reference that does not parse is a finding too, with its error. That is
    the `keeper://` case: a scheme nobody implements, written down three times
    in a template, invisible to every check because nothing ever looked.
    """
    root = os.path.abspath(root)
    # Paths are reported relative to the tree the caller named, not to whatever
    # subdirectory the walk happens to be in: `find(root, ["skills"])` said
    # `workload/SKILL.md` where the caller means `skills/workload/SKILL.md`.
    base = os.path.abspath(base) if base else root
    names = list(paths) if paths else candidate_files(root, runner=runner)
    findings: list[Finding] = []
    for name in names:
        full = name if os.path.isabs(name) else os.path.join(root, name)
        if os.path.islink(full):
            # The discovery symlinks (.claude/skills and friends) point back
            # into the tree. Following them counted every skill three times:
            # measured on this repo before the check existed.
            continue
        if os.path.isdir(full):
            findings.extend(find(full, runner=runner, base=base))
            continue
        text = readable_text(full)
        if text is None or "://" not in text:
            continue
        rel = os.path.relpath(full, base)
        for number, line in enumerate(text.splitlines(), 1):
            for raw, follower in refs_mod.iter_in_text(line):
                findings.append(_classify(rel, number, raw, follower))
    return findings


def _classify(path: str, line: int, raw: str, follower: str = "") -> Finding:
    if is_example(raw) or follower in ("<", "{"):
        return Finding(path=path, line=line, raw=raw, example=True,
                       error="an example, not a live reference")
    try:
        parsed = refs_mod.parse(raw)
    except ReferenceError_ as problem:
        return Finding(path=path, line=line, raw=raw, error=str(problem))
    return Finding(path=path, line=line, raw=raw, ref=parsed)


def is_example(raw: str) -> bool:
    """True when the reference carries a placeholder rather than a location."""
    return any(mark in raw for mark in PLACEHOLDER_MARKS)


def unique_refs(findings) -> list:
    """The distinct references among findings, in first-seen order."""
    seen = {}
    for finding in findings:
        if finding.ref is None:
            continue
        key = finding.ref.canonical
        seen.setdefault(key, finding.ref)
    return list(seen.values())


def group_by_ref(findings, *, examples: bool = True) -> dict:
    """Reference text -> the places it is written down."""
    grouped: dict = {}
    for finding in findings:
        if finding.example and not examples:
            continue
        key = finding.ref.canonical if finding.ref is not None else finding.raw
        grouped.setdefault(key, []).append(finding)
    return grouped


def in_repo(root: str) -> bool:
    """True when `root` is inside a git work tree."""
    try:
        done = subprocess.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git here
        return False
    return done.returncode == 0 and done.stdout.strip() == "true"
