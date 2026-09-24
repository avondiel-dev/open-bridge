#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pytest suite for scripts/check-commands-doc.py.

CONTRACT, this file is the authoritative spec for that surface.

WHY THIS EXISTS. `docs/commands.md` is the CORE command reference. It fell
fifteen skills behind the tree without anybody noticing, and it named a short
form (`/promote`) that the backing skill never declared. Two directions are
checked:

  - every `scope: core` skill that presents itself as a command is listed.
    A skill presents itself as a command when its `description:` names a
    quoted slash trigger (`"/name"`), and it is not switched off with
    `user-invocable: false`;
  - every row the document lists has a skill behind it: the command is
    `/<skill name>` of an existing `scope: core` skill, the backing-skill
    column names that same skill, and every short form is a slash trigger
    the skill itself declares.

    check-commands-doc.py [--root DIR]
        exit 0: document and tree agree
        exit 1: one line per finding
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check-commands-doc.py"


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


cd = _load(SCRIPT, "check_commands_doc_under_test")

HEADER = "| Command | Short form | Backing skill | Action |\n|---|---|---|---|\n"


def skill(root: Path, name: str, description: str, scope: str = "core",
          extra: str = "") -> None:
    d = root / "skills" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: '{description}'\n{extra}"
        f"metadata:\n  scope: {scope}\n---\n\n# {name}\n", encoding="utf-8")


def doc(root: Path, rows: str) -> None:
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "commands.md").write_text(
        "# Commands\n\n" + HEADER + rows, encoding="utf-8")


def run(root: Path, capsys) -> tuple[int, str]:
    capsys.readouterr()
    code = cd.main(["--root", str(root)])
    return code, capsys.readouterr().out


def base(root: Path) -> None:
    skill(root, "briefing", 'Daily briefing. Trigger: "/briefing", "good morning".')
    skill(root, "bridge-overlay", 'Overlays. Trigger: "/overlay", "org overlay".')


def test_a_complete_document_passes(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_core_command_skill_missing_from_the_document_is_flagged(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path, "| `/briefing` | | `briefing` | Daily briefing |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "bridge-overlay" in out and "missing" in out


def test_a_skill_without_a_slash_trigger_is_not_required(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "html-canvas", 'Builds HTML pages. Use for "explainer".')
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_an_unquoted_slash_mention_in_prose_is_not_a_trigger(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "task-close", 'Proposals for later review via /bridge-learn.')
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_non_core_skill_is_not_required(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "private-thing", 'Trigger: "/private-thing".', scope="user")
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_user_invocable_false_is_not_required(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "hidden", 'Trigger: "/hidden".', extra="user-invocable: false\n")
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_listed_command_with_no_skill_behind_it_is_flagged(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n"
        "| `/crew` | | `crew` | Retired |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "/crew" in out


def test_a_listed_non_core_skill_is_flagged(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "private-thing", 'Trigger: "/private-thing".', scope="user")
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n"
        "| `/private-thing` | | `private-thing` | Private |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "/private-thing" in out


def test_a_listed_core_skill_without_a_trigger_is_allowed(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "remote", 'Machines. Triggers: "remote", "wake".')
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n"
        "| `/remote` | | `remote` | Machines |\n")
    assert run(tmp_path, capsys) == (0, "")


def test_a_short_form_the_skill_never_declared_is_flagged(tmp_path, capsys):
    base(tmp_path)
    skill(tmp_path, "bridge-promote", 'Promote. Trigger: "/bridge-promote", "promote".')
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n"
        "| `/bridge-promote` | `/promote` | `bridge-promote` | Promote |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "/promote" in out and "bridge-promote" in out


def test_a_short_form_used_as_the_command_is_flagged(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/overlay` | | `bridge-overlay` | Overlays |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "/overlay" in out


def test_a_backing_skill_that_differs_from_the_command_is_flagged(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `bridge-overlay` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "/briefing" in out


def test_a_command_listed_twice_is_flagged(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/briefing` | | `briefing` | Again |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n")
    code, out = run(tmp_path, capsys)
    assert code == 1
    assert "twice" in out


def test_a_table_inside_a_code_fence_is_not_read(tmp_path, capsys):
    base(tmp_path)
    doc(tmp_path,
        "| `/briefing` | | `briefing` | Daily briefing |\n"
        "| `/bridge-overlay` | `/overlay` | `bridge-overlay` | Overlays |\n"
        "\n```\n| `/crew` | | `crew` | example |\n```\n")
    assert run(tmp_path, capsys) == (0, "")


def test_the_shipped_tree_agrees_with_its_document(capsys):
    assert run(REPO_ROOT, capsys) == (0, "")
