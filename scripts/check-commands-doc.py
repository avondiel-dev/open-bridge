#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The CORE command reference lists every CORE command skill, and nothing else.

`docs/commands.md` holds one table, `| Command | Short form | Backing skill |
Action |`. It drifts in two directions, and both have happened: skills ship
without a row, and a row names a command that no skill declares.

Which skills must be listed. A skill counts as a command when all of these
hold, read from its `SKILL.md` frontmatter only:

  - `metadata.scope` is `core` (this is the CORE reference; an instance's own
    skills are its own business);
  - its `description:` names at least one quoted slash trigger, `"/name"`.
    That is how a skill author presents a skill as a command. A slash word in
    running prose ("review it via /bridge-learn") is a cross-reference, not a
    trigger, so only a quoted one counts;
  - it does not set `user-invocable: false` (top level or under `metadata`).

In Claude Code the registered command is always the skill's name, so the
Command column must be `/<skill name>`. A different quoted slash trigger in the
description (`"/overlay"` on `bridge-overlay`) is a short form the agent
matches in a message, not a second registered command; it goes into the Short
form column, and only a short form the skill itself declares may appear there.

Which rows are allowed. Every row must name an existing `scope: core` skill as
`/<name>`, repeat that name in the Backing skill column, and appear once. A
CORE skill that declares no slash trigger may still be listed (`/remote`);
it is not required.

    python3 scripts/check-commands-doc.py [--root DIR]

Exit 0 when the document and the tree agree, 1 with one line per finding.
Reads only; never writes.

Contract: `scripts/tests/test_commands_doc.py`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

DOC = "docs/commands.md"
FRONTMATTER = re.compile(r"\A---\n(.*?)\n---", re.S)
QUOTED_SLASH = re.compile(r"\"(/[a-z0-9][a-z0-9-]*)")
TICKED = re.compile(r"`(/?[a-z0-9][a-z0-9-]*)`")


def load_skills(root: Path) -> dict[str, dict]:
    """name -> {scope, triggers, invocable} for every skills/*/SKILL.md."""
    skills: dict[str, dict] = {}
    for path in sorted((root / "skills").glob("*/SKILL.md")):
        match = FRONTMATTER.match(path.read_text(encoding="utf-8"))
        if not match:
            continue
        fm = yaml.safe_load(match.group(1)) or {}
        meta = fm.get("metadata") or {}
        name = fm.get("name") or path.parent.name
        invocable = fm.get("user-invocable", meta.get("user-invocable", True))
        skills[name] = {
            "scope": meta.get("scope"),
            "triggers": set(QUOTED_SLASH.findall(str(fm.get("description", "")))),
            "invocable": invocable is not False,
        }
    return skills


def required(skills: dict[str, dict]) -> set[str]:
    return {name for name, s in skills.items()
            if s["scope"] == "core" and s["triggers"] and s["invocable"]}


def table_rows(text: str) -> list[tuple[int, list[str]]]:
    """Rows of the `| Command |` table, outside code fences."""
    rows: list[tuple[int, list[str]]] = []
    fenced = in_table = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            in_table = False
            continue
        if fenced:
            continue
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and cells[0].lower() == "command":
            in_table = True
            continue
        if not in_table or all(re.fullmatch(r":?-+:?", c) for c in cells if c):
            continue
        rows.append((lineno, cells))
    return rows


def check(root: Path) -> list[str]:
    skills = load_skills(root)
    doc = root / DOC
    if not doc.is_file():
        return [f"{DOC}: missing"]
    findings: list[str] = []
    listed: dict[str, int] = {}
    for lineno, cells in table_rows(doc.read_text(encoding="utf-8")):
        where = f"{DOC}:{lineno}"
        if len(cells) < 4:
            findings.append(f"{where}: expected 4 columns, found {len(cells)}")
            continue
        command_cell, short_cell, backing_cell = cells[0], cells[1], cells[2]
        commands = TICKED.findall(command_cell)
        if len(commands) != 1 or not commands[0].startswith("/"):
            findings.append(f"{where}: Command column must hold one `/name`, "
                            f"found {command_cell!r}")
            continue
        command = commands[0]
        name = command[1:]
        if name in listed:
            findings.append(f"{where}: {command} listed twice "
                            f"(first at line {listed[name]})")
            continue
        listed[name] = lineno
        s = skills.get(name)
        if s is None:
            owners = sorted(n for n, x in skills.items() if command in x["triggers"])
            hint = (f"; it is a short form of {', '.join(owners)}, whose command "
                    f"is /{owners[0]}") if owners else ""
            findings.append(f"{where}: {command} has no skill behind it{hint}")
            continue
        if s["scope"] != "core":
            findings.append(f"{where}: {command} is backed by a scope: "
                            f"{s['scope']} skill; this is the CORE reference")
        backing = TICKED.findall(backing_cell)
        if backing != [name]:
            findings.append(f"{where}: {command} names backing skill "
                            f"{backing_cell!r}, expected `{name}`")
        for short in TICKED.findall(short_cell):
            if short not in s["triggers"] or short == command:
                findings.append(f"{where}: short form {short} is not a slash "
                                f"trigger that {name} declares")
    for name in sorted(required(skills) - set(listed)):
        findings.append(f"{DOC}: /{name} missing; skills/{name} is a CORE "
                        f"command skill")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args(argv)
    findings = check(Path(args.root))
    for line in findings:
        print(line)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
