#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pytest suite for scripts/check-where-things-live.py.

CONTRACT, this file is the authoritative spec for that surface.

WHY THIS EXISTS. `docs/where-things-live.md` answers "I have this question
right now, where is the answer?" with a two-column table: a question in the
asker's own words on the left, the file that answers it on the right. An
instance appends its own rows in `docs/where-things-live.local.md`. Two
properties decay first and are checked here:

  - the left column is a QUESTION (ends in "?"), not a topic;
  - the right column is a LINK that resolves, including a `#section` anchor
    where one is given.

    check-where-things-live.py [--root DIR]
        exit 0: every row is a question and every link resolves
        exit 1: one line per finding
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-where-things-live.py"


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


cw = _load(SCRIPT, "check_where_things_live_under_test")

HEADER = "| Question | Where |\n|---|---|\n"


def tree(root: Path, core_rows: str, local_rows: str | None = None) -> None:
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "rules").mkdir(exist_ok=True)
    (root / "rules" / "gate.md").write_text(
        "# Gate\n\n## When the gate fires\n\ntext\n\n## `code` and *emphasis*, too\n",
        encoding="utf-8")
    (root / "docs" / "where-things-live.md").write_text(
        "# Where things live\n\n## Config\n\n" + HEADER + core_rows, encoding="utf-8")
    if local_rows is not None:
        (root / "docs" / "where-things-live.local.md").write_text(
            "# This instance\n\n" + HEADER + local_rows, encoding="utf-8")


def run(root: Path, capsys) -> tuple[int, str]:
    capsys.readouterr()
    code = cw.main(["--root", str(root)])
    return code, capsys.readouterr().out


def test_a_question_with_a_resolving_link_passes(tmp_path, capsys):
    tree(tmp_path, "| When does the gate fire? | [`rules/gate.md`](../rules/gate.md) |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_topic_row_is_flagged(tmp_path, capsys):
    tree(tmp_path, "| Gate conventions | [`rules/gate.md`](../rules/gate.md) |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "where-things-live.md:7" in out and "question" in out


def test_a_dead_link_is_flagged(tmp_path, capsys):
    tree(tmp_path, "| Where is the gone file? | [`rules/gone.md`](../rules/gone.md) |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1 and "rules/gone.md" in out and "does not exist" in out


def test_a_row_without_any_link_is_flagged(tmp_path, capsys):
    tree(tmp_path, "| Where is the gate? | `rules/gate.md` |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1 and "no link" in out


def test_a_resolving_anchor_passes(tmp_path, capsys):
    tree(tmp_path, "| When does it fire? | [x](../rules/gate.md#when-the-gate-fires) |\n"
                   "| Does code count? | [y](../rules/gate.md#code-and-emphasis-too) |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_dead_anchor_is_flagged(tmp_path, capsys):
    tree(tmp_path, "| When does it fire? | [x](../rules/gate.md#no-such-section) |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1 and "#no-such-section" in out


def test_a_directory_link_passes(tmp_path, capsys):
    tree(tmp_path, "| Where do rules live? | [`rules/`](../rules/) |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_an_external_url_is_not_checked(tmp_path, capsys):
    tree(tmp_path, "| Where is the wiki? | [wiki](https://example.org/wiki) |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_the_local_file_is_optional(tmp_path, capsys):
    tree(tmp_path, "| When does the gate fire? | [g](../rules/gate.md) |\n")
    assert not (tmp_path / "docs" / "where-things-live.local.md").exists()
    assert run(tmp_path, capsys)[0] == 0


def test_the_local_file_is_held_to_the_same_rules(tmp_path, capsys):
    tree(tmp_path, "| When does the gate fire? | [g](../rules/gate.md) |\n",
         local_rows="| Our wiki | [w](../rules/nope.md) |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert out.count("where-things-live.local.md:") == 2


def test_a_local_row_repeating_a_core_question_is_flagged(tmp_path, capsys):
    tree(tmp_path, "| When does the gate fire? | [g](../rules/gate.md) |\n",
         local_rows="| When does the gate  fire? | [g](../rules/gate.md) |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1 and "already asked" in out


def test_a_table_inside_a_code_fence_is_an_example(tmp_path, capsys):
    tree(tmp_path, "| When does the gate fire? | [g](../rules/gate.md) |\n\n"
                   "```markdown\n| A topic | [x](../nowhere.md) |\n```\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_missing_map_is_a_finding(tmp_path, capsys):
    (tmp_path / "docs").mkdir()
    code, out = run(tmp_path, capsys)
    assert code == 1 and "where-things-live.md" in out


def test_a_pipe_inside_backticks_does_not_split_the_row(tmp_path, capsys):
    tree(tmp_path, "| What does `a \\| b` mean here? | [g](../rules/gate.md) |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_the_shipped_tree_passes():
    assert cw.main(["--root", str(REPO_ROOT)]) == 0
