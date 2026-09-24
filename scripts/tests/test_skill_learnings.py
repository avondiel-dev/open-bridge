#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pytest suite for scripts/check-skill-learnings.py.

CONTRACT, this file is the authoritative spec for that surface.

WHY THIS EXISTS. A skill may keep a journal of lessons about itself,
`skills/<name>/LEARNINGS.md`, plus a routing block in its SKILL.md (marked
`<!-- lessons-routing -->`) that says which kind of lesson goes where
(`docs/skill-learnings.md`). The convention is opt-in per skill. The one
thing it must not do is exist by halves: a journal nobody is pointed at is
never read, and a routing block pointing at no journal sends lessons nowhere.

    check-skill-learnings.py [--root DIR]
        exit 0: every skill has both halves or neither, and every journal
        heading is dated (`## YYYY-MM-DD: <lesson>`)
        exit 1: one line per finding
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-skill-learnings.py"


def _load(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


csl = _load(SCRIPT, "check_skill_learnings_under_test")

BLOCK = "## Where lessons go\n<!-- lessons-routing -->\n- a trap of this skill: LEARNINGS.md\n"


def skill(root: Path, name: str, *, block: bool = False, journal: str | None = None) -> Path:
    directory = root / "skills" / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\n---\n# {name}\n\n" + (BLOCK if block else ""), encoding="utf-8")
    if journal is not None:
        (directory / "LEARNINGS.md").write_text(journal, encoding="utf-8")
    return directory


GOOD_JOURNAL = ("# Learnings\n\n## 2026-09-24: gh returns 404 JSON on stdout\n"
                "What: ...\nWhy it matters: ...\n")


def test_a_skill_without_either_half_is_fine(tmp_path):
    skill(tmp_path, "plain")
    assert csl.main(["--root", str(tmp_path)]) == 0


def test_a_skill_with_both_halves_is_fine(tmp_path):
    skill(tmp_path, "both", block=True, journal=GOOD_JOURNAL)
    assert csl.main(["--root", str(tmp_path)]) == 0


def test_a_journal_without_a_routing_block_is_drift(tmp_path, capsys):
    skill(tmp_path, "orphan-journal", journal=GOOD_JOURNAL)
    capsys.readouterr()
    assert csl.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "skills/orphan-journal" in out and "routing block" in out


def test_a_routing_block_without_a_journal_is_drift(tmp_path, capsys):
    skill(tmp_path, "orphan-block", block=True)
    capsys.readouterr()
    assert csl.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "skills/orphan-block" in out and "LEARNINGS.md" in out


def test_an_undated_journal_heading_is_flagged(tmp_path, capsys):
    skill(tmp_path, "undated", block=True,
          journal="# Learnings\n\n## gh returns 404 JSON on stdout\nWhat: ...\n")
    capsys.readouterr()
    assert csl.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "LEARNINGS.md:3" in out and "dated" in out


def test_an_empty_journal_with_its_block_is_fine(tmp_path):
    skill(tmp_path, "fresh", block=True, journal="# Learnings\n")
    assert csl.main(["--root", str(tmp_path)]) == 0


def test_reserved_underscore_directories_are_skipped(tmp_path):
    skill(tmp_path, "_template", journal=GOOD_JOURNAL)
    assert csl.main(["--root", str(tmp_path)]) == 0


def test_the_shipped_tree_passes():
    assert csl.main(["--root", str(REPO_ROOT)]) == 0
