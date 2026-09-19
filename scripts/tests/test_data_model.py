#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pytest suite for scripts/data-model.py.

CONTRACT, this file is the authoritative spec for that surface.

    Every config family the tree has is described EXACTLY ONCE: in
    docs/data-model.yaml when CORE ships it, in work/data-model.yaml when only
    the instance has it. A row names a family that exists. The table in
    docs/data-model.md and the ring in docs/index.html are generated from the
    yaml and are drift the moment they differ from it.

WHY. The layout was documented in four places and drawn in two, and the
drawing on the landing page went on saying "the agent reads every ring at
session start" for weeks after the context index made that untrue. Nothing
failed, because nothing compared the picture with anything.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = REPO_ROOT / "scripts" / "data-model.py"


def _load():
    spec = importlib.util.spec_from_file_location("data_model", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dm = _load()

ROW = {"object": "one thing", "island": "user", "lives": "user-branch",
       "references": [], "writer": "a person", "read": "named"}
HEAD = """stores:
  user-branch: {short: "user branch"}
reads:
  named: {short: "by name"}
  start: {short: "at start"}
families:
"""


def _row(path: str, **over) -> str:
    fields = dict(ROW, path=path, **over)
    lines = [f"  - path: {fields.pop('path')}"]
    for key, value in fields.items():
        lines.append(f"    {key}: {value!r}" if not isinstance(value, list) else f"    {key}: []")
    return "\n".join(lines) + "\n"


def _tree(tmp: Path, families: list[str], core_rows: list[str], local_rows: list[str] | None = None) -> Path:
    for fam in families:
        (tmp / fam).mkdir(parents=True, exist_ok=True)
        if fam.split("/")[0] in ("identity", "infra", "workflow"):
            (tmp / fam / "_template.yaml").write_text("schema_version: 1\n", encoding="utf-8")
    (tmp / "docs").mkdir(exist_ok=True)
    (tmp / "docs" / "data-model.yaml").write_text(HEAD + "".join(core_rows), encoding="utf-8")
    if local_rows is not None:
        (tmp / "work").mkdir(exist_ok=True)
        (tmp / "work" / "data-model.yaml").write_text("families:\n" + "".join(local_rows), encoding="utf-8")
    return tmp


def _problems(root: Path) -> list[str]:
    return dm.check_rows(dm.load_model(root), dm.tree_families(root))


def test_every_family_described_once_is_clean(tmp_path):
    root = _tree(tmp_path, ["identity/personas", "work"],
                 [_row("identity/personas/"), _row("work/")])
    assert _problems(root) == []


def test_a_family_without_a_row_is_named(tmp_path):
    root = _tree(tmp_path, ["identity/personas", "infra/remotes", "work"],
                 [_row("identity/personas/"), _row("work/")])
    found = _problems(root)
    assert any("infra/remotes/" in p and "no row" in p for p in found), found


def test_a_second_row_for_one_family_is_named(tmp_path):
    root = _tree(tmp_path, ["identity/personas", "work"],
                 [_row("identity/personas/"), _row("identity/personas"), _row("work/")])
    assert any("described twice" in p for p in _problems(root))


def test_a_row_for_a_folder_the_tree_lacks_is_named(tmp_path):
    root = _tree(tmp_path, ["work"], [_row("work/"), _row("identity/gone/")])
    assert any("identity/gone/" in p and "no such family" in p for p in _problems(root))


def test_an_unknown_read_value_and_store_are_named(tmp_path):
    root = _tree(tmp_path, ["work"], [_row("work/", read="sometimes", lives="nowhere")])
    found = " ".join(_problems(root))
    assert "sometimes" in found and "nowhere" in found


def test_an_instance_family_is_described_in_work_and_never_reaches_the_doc(tmp_path):
    """The case that would turn every fork red if the model were CORE only."""
    root = _tree(tmp_path, ["workflow/meetings", "work"], [_row("work/")],
                 local_rows=[_row("workflow/meetings/")])
    model = dm.load_model(root)
    assert dm.check_rows(model, dm.tree_families(root)) == []
    assert "workflow/meetings" not in dm.render_table(model), \
        "an instance's own row leaked into the CORE table"


def test_the_instance_file_cannot_hide_a_core_row_twice(tmp_path):
    root = _tree(tmp_path, ["work"], [_row("work/")], local_rows=[_row("work/")])
    assert any("described twice" in p for p in _problems(root))


def test_the_repository_itself_is_in_sync():
    done = subprocess.run([sys.executable, str(CLI)], cwd=REPO_ROOT,
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_every_needle_bites():
    done = subprocess.run([sys.executable, str(CLI), "--mutate"], cwd=REPO_ROOT,
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
