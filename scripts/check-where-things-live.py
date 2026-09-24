#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Every row of the question map is a question, and every answer it points at exists.

`docs/where-things-live.md` maps a question, in the words somebody asks it, to
the file that answers it. An instance appends its own rows in
`docs/where-things-live.local.md`. The map is worth something only while two
properties hold, and both decay quietly:

  - the left column is a question. A row phrased as a topic ("Tracker
    conventions") makes the reader deduce whether it is theirs, which is the
    work the map exists to save;
  - the right column resolves. A link at a renamed file or a vanished section
    sends the reader nowhere at the moment they needed it.

    python3 scripts/check-where-things-live.py [--root DIR]

Exit 0 when both hold for every row of both files, 1 with one line per
finding. Reads only; never writes.

Contract: `scripts/tests/test_where_things_live.py`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CORE_MAP = "docs/where-things-live.md"
LOCAL_MAP = "docs/where-things-live.local.md"

MD_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SEPARATOR = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")


def unfenced(text: str) -> list[tuple[int, str]]:
    """(line number, line) outside ``` fences: a table in a code block is an
    example of the format, not a row of the map."""
    lines: list[tuple[int, str]] = []
    fenced = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            lines.append((lineno, line))
    return lines


def cells(line: str) -> list[str]:
    """Split a table row on unescaped pipes; `\\|` stays inside its cell."""
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", body)]


def rows(text: str) -> list[tuple[int, str, str]]:
    """(line number, question, answer) for every body row of every table."""
    lines = unfenced(text)
    found: list[tuple[int, str, str]] = []
    for index, (lineno, line) in enumerate(lines):
        if not line.lstrip().startswith("|") or SEPARATOR.match(line.strip()):
            continue
        following = lines[index + 1][1].strip() if index + 1 < len(lines) else ""
        if SEPARATOR.match(following):
            continue  # the header row
        parts = cells(line)
        if len(parts) >= 2:
            found.append((lineno, parts[0], parts[1]))
    return found


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: inline markup dropped, lower case,
    punctuation removed, spaces become hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").lower().strip()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    for _, line in unfenced(path.read_text(encoding="utf-8", errors="replace")):
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not match:
            continue
        base = slug(match.group(1))
        count = seen.get(base, 0)
        seen[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def normalise(question: str) -> str:
    return " ".join(question.lower().split())


def check_file(root: Path, rel: str, core_questions: set[str] | None) -> tuple[list[str], set[str]]:
    path = root / rel
    findings: list[str] = []
    questions: set[str] = set()
    for lineno, question, answer in rows(path.read_text(encoding="utf-8", errors="replace")):
        where = f"{rel}:{lineno}"
        if not question.rstrip().endswith("?"):
            findings.append(f"{where}: {question!r} is a topic, not a question; "
                            "phrase it the way somebody would ask it")
        key = normalise(question)
        if core_questions is not None and key in core_questions:
            findings.append(f"{where}: {question!r} is already asked in {CORE_MAP}; "
                            "an instance row adds a question, it does not repeat one")
        questions.add(key)
        targets = MD_LINK.findall(answer)
        if not targets:
            findings.append(f"{where}: the answer column has no link; "
                            "write it as [`path`](relative/path)")
        for target in targets:
            if "://" in target or target.startswith("mailto:"):
                continue
            file_part, _, anchor = target.partition("#")
            resolved = (path.parent / file_part).resolve() if file_part else path
            if not resolved.exists():
                findings.append(f"{where}: {target} does not exist")
            elif anchor and resolved.is_file() and resolved.suffix == ".md" \
                    and anchor not in anchors(resolved):
                findings.append(f"{where}: {target} names a section (#{anchor}) "
                                f"that {resolved.name} does not have")
    return findings, questions


def check(root: Path) -> list[str]:
    if not (root / CORE_MAP).is_file():
        return [f"{CORE_MAP}: the map is missing"]
    findings, core_questions = check_file(root, CORE_MAP, None)
    if (root / LOCAL_MAP).is_file():
        local, _ = check_file(root, LOCAL_MAP, core_questions)
        findings += local
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="check-where-things-live",
                                     description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--root", default=".", help="repo root (default: cwd)")
    args = parser.parse_args(argv)
    findings = check(Path(args.root))
    for finding in findings:
        print(finding)
    if findings:
        print(f"check-where-things-live: {len(findings)} finding(s)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
