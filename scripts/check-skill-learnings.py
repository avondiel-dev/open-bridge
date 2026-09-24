#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A skill's lesson journal and its routing block exist together or not at all.

A skill may keep `skills/<name>/LEARNINGS.md`, an append-only journal of
lessons about that one skill, and a routing block in its SKILL.md (marked
`<!-- lessons-routing -->`) that says which kind of lesson goes where. Both
are opt-in per skill (`docs/skill-learnings.md`). Half of the pair is drift:
a journal no routing block points at is never read, and a routing block with
no journal sends lessons nowhere. Journal headings carry their date, so the
curator can tell a fresh entry from a matured one.

    python3 scripts/check-skill-learnings.py [--root DIR]

Exit 0 when every skill has both halves or neither, 1 with one line per
finding. Reads only; never writes.

Contract: `scripts/tests/test_skill_learnings.py`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROUTING_MARKER = "<!-- lessons-routing -->"
ENTRY_HEADING_RE = re.compile(r"^## \d{4}-\d{2}-\d{2}: \S")


def check(root: Path) -> list[str]:
    findings: list[str] = []
    for directory in sorted((root / "skills").iterdir() if (root / "skills").is_dir() else []):
        if not directory.is_dir() or directory.name.startswith(("_", ".")):
            continue
        skill_md = directory / "SKILL.md"
        journal = directory / "LEARNINGS.md"
        rel = f"skills/{directory.name}"
        has_block = skill_md.is_file() and ROUTING_MARKER in skill_md.read_text(
            encoding="utf-8", errors="replace")
        has_journal = journal.is_file()

        if has_journal and not has_block:
            findings.append(f"{rel}: LEARNINGS.md exists but SKILL.md has no routing block "
                            f"({ROUTING_MARKER}), so nothing points a reader at it")
        if has_block and not has_journal:
            findings.append(f"{rel}: SKILL.md carries a routing block but there is no "
                            "LEARNINGS.md for it to send lessons to")
        if has_journal:
            lines = journal.read_text(encoding="utf-8", errors="replace").splitlines()
            for lineno, line in enumerate(lines, start=1):
                if line.startswith("## ") and not ENTRY_HEADING_RE.match(line):
                    findings.append(f"{rel}/LEARNINGS.md:{lineno}: entry heading is not "
                                    f"dated, expected '## YYYY-MM-DD: <lesson>': {line!r}")
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="check-skill-learnings", description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--root", default=".", help="repo root (default: cwd)")
    args = parser.parse_args(argv)
    findings = check(Path(args.root))
    for finding in findings:
        print(finding)
    if findings:
        print(f"check-skill-learnings: {len(findings)} finding(s)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
