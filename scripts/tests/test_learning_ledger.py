#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pytest suite for scripts/learning-ledger.py and the proposal schema.

CONTRACT, this file is the authoritative spec for that surface.

WHY THIS EXISTS. The learning loop (`work/_learning/`, `/bridge-learn`) kept
its state in three places that nothing held together: the folder a proposal
file sits in, the `status:` in its own frontmatter, and the row an agent typed
into `audit-trail.md` by hand. `scripts/learning-ledger.py` is the one writer
and checker for that state:

    fingerprint <id>        store `recurrence_fingerprint` on an implemented
                            proposal: `<target.path>#<id without its date>`.
    recurrences [--json]    implemented proposals whose target.path shows up
                            again later (a newer proposal, a postmortem, an
                            audit-history file), listed as `recurred: <date>`.
                            Evidence only; never changes a status.

Tests build a throwaway Bridge root under `tmp_path` and pass it with
`--root`, never touching the real repo's `work/_learning/`.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "learning-ledger.py"
CANONICAL_SCHEMA = REPO_ROOT / "work" / "_learning" / "_schema.proposal.yaml"
SKILL_SCHEMA = (REPO_ROOT / "skills" / "task-close-postmortem" / "references"
                / "_schema.proposal.yaml")


def _load(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve their module by name
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


ll = _load(SCRIPT, "learning_ledger_under_test")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def bridge_root(tmp_path: Path) -> Path:
    root = tmp_path / "bridge"
    learning = root / "work" / "_learning"
    for sub in ("proposals/accepted", "proposals/rejected", "postmortems", "audit-history"):
        (learning / sub).mkdir(parents=True)
    (learning / "audit-trail.md").write_text(
        "# Learning Audit-Trail\n\n"
        "| Timestamp | Proposal ID | Transition | Reason | Commit |\n"
        "|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=root, check=True)
    return root


def proposal(root: Path, pid: str, *, folder: str = "", status: str = "pending",
             target_path: str = "skills/demo/SKILL.md", target_type: str = "skill",
             created: str | None = None, extra: dict | None = None, body: str = "Body.\n") -> Path:
    data = {
        "id": pid,
        "created": created or pid[:10],
        "source": {"type": "postmortem", "task_slug": "demo-task",
                   "evidence": ["work/done/2026-01/demo-task/STATUS.md"]},
        "severity": "P2",
        "status": status,
        "scope": "core",
        "target": {"type": target_type, "path": target_path, "action": "edit"},
        "proposal_type": "structured",
    }
    data.update(extra or {})
    directory = root / "work" / "_learning" / "proposals" / folder
    path = directory / f"{pid}.md"
    path.write_text("---\n" + yaml.safe_dump(data, sort_keys=False) + "---\n\n" + body,
                    encoding="utf-8")
    return path


def trail_rows(root: Path) -> list[str]:
    text = (root / "work" / "_learning" / "audit-trail.md").read_text(encoding="utf-8")
    return [line for line in text.splitlines()
            if line.startswith("| 2") or line.startswith("| %")]


def frontmatter(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8").split("---", 2)[1])


# ---------------------------------------------------------------------------
# Schema (#202): one definition, verification optional, lifecycle fields
# ---------------------------------------------------------------------------

def _validator():
    # CI installs jsonschema for this suite; a skip here only hides the schema
    # half on a machine without it, never the ledger half below.
    jsonschema = pytest.importorskip("jsonschema")
    schema = yaml.safe_load(CANONICAL_SCHEMA.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def _base() -> dict:
    return {
        "id": "2026-01-02-demo-task-tighten-trigger",
        "created": "2026-01-02",
        "source": {"type": "postmortem", "evidence": ["work/done/x/STATUS.md"]},
        "severity": "P2",
        "status": "pending",
        "scope": "core",
        "target": {"type": "skill", "path": "skills/demo/SKILL.md", "action": "edit"},
        "proposal_type": "structured",
    }


def test_schema_accepts_a_proposal_without_verification():
    assert list(_validator().iter_errors(_base())) == []


def test_schema_accepts_a_verification_block():
    data = _base()
    data["verification"] = {"kind": "deterministic", "command": "pytest -q",
                            "before": "3 failed", "after": "0 failed"}
    assert list(_validator().iter_errors(data)) == []


def test_schema_rejects_an_unknown_verification_kind():
    data = _base()
    data["verification"] = {"kind": "vibes"}
    assert list(_validator().iter_errors(data))


def test_schema_accepts_the_lifecycle_fields_the_review_workflow_writes():
    data = _base()
    data.update({"status": "rejected", "rejected_at": "2026-01-03",
                 "reject_reason": "covered elsewhere"})
    assert list(_validator().iter_errors(data)) == []
    data = _base()
    data.update({"status": "implemented", "accepted_at": "2026-01-03",
                 "implemented_commit": "4f3a2b1",
                 "recurrence_fingerprint": "skills/demo/SKILL.md#demo-task-tighten-trigger"})
    assert list(_validator().iter_errors(data)) == []
    data = _base()
    data.update({"status": "deferred", "deferred_at": "2026-01-03",
                 "defer_until": "phase-3", "defer_reason": ""})
    assert list(_validator().iter_errors(data)) == []


def test_schema_accepts_the_capability_gap_source_the_broker_writes():
    data = _base()
    data["source"]["type"] = "capability-gap"
    assert list(_validator().iter_errors(data)) == []


def test_schema_still_refuses_an_undeclared_field():
    data = _base()
    data["mood"] = "optimistic"
    assert list(_validator().iter_errors(data))


def test_the_skill_copy_is_a_pointer_not_a_second_definition():
    pointer = yaml.safe_load(SKILL_SCHEMA.read_text(encoding="utf-8"))
    assert "properties" not in pointer
    assert "verification" not in SKILL_SCHEMA.read_text(encoding="utf-8")
    target = (SKILL_SCHEMA.parent / pointer["$ref"]).resolve()
    assert target == CANONICAL_SCHEMA.resolve()


# ---------------------------------------------------------------------------
# fingerprint / recurrences (#202)
# ---------------------------------------------------------------------------


def test_fingerprint_stores_target_path_and_gap_slug(tmp_path):
    root = bridge_root(tmp_path)
    path = proposal(root, "2026-01-02-demo-task-tighten-trigger", folder="accepted",
                    status="implemented")

    assert ll.main(["--root", str(root), "fingerprint",
                    "2026-01-02-demo-task-tighten-trigger"]) == 0
    assert frontmatter(path)["recurrence_fingerprint"] == \
        "skills/demo/SKILL.md#demo-task-tighten-trigger"
    assert path.read_text(encoding="utf-8").endswith("Body.\n")


def test_fingerprint_is_idempotent(tmp_path):
    root = bridge_root(tmp_path)
    path = proposal(root, "2026-01-02-demo-task-tighten-trigger", folder="accepted",
                    status="implemented")
    for _ in range(2):
        assert ll.main(["--root", str(root), "fingerprint",
                        "2026-01-02-demo-task-tighten-trigger"]) == 0
    assert path.read_text(encoding="utf-8").count("recurrence_fingerprint") == 1


def test_fingerprint_refuses_a_proposal_that_is_not_implemented(tmp_path, capsys):
    root = bridge_root(tmp_path)
    path = proposal(root, "2026-01-02-demo-task-tighten-trigger")

    assert ll.main(["--root", str(root), "fingerprint",
                    "2026-01-02-demo-task-tighten-trigger"]) == 2
    assert "recurrence_fingerprint" not in path.read_text(encoding="utf-8")


def _implemented(root, pid="2026-01-02-demo-task-tighten-trigger", on="2026-01-05"):
    proposal(root, pid, folder="accepted", status="implemented",
             extra={"accepted_at": on,
                    "recurrence_fingerprint": f"skills/demo/SKILL.md#{pid[11:]}"})


def test_recurrences_flags_a_later_proposal_on_the_same_target(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _implemented(root)
    proposal(root, "2026-02-01-other-task-trigger-again")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "recurrences", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == [{"id": "2026-01-02-demo-task-tighten-trigger",
                     "fingerprint": "skills/demo/SKILL.md#demo-task-tighten-trigger",
                     "recurred": "2026-02-01",
                     "evidence": "work/_learning/proposals/2026-02-01-other-task-trigger-again.md"}]


def test_recurrences_flags_a_later_postmortem_naming_the_target(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _implemented(root)
    (root / "work" / "_learning" / "postmortems" / "2026-03-04-some-task.md").write_text(
        "Burned time in skills/demo/SKILL.md again.\n", encoding="utf-8")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "recurrences"]) == 0
    out = capsys.readouterr().out
    assert "recurred: 2026-03-04" in out
    assert "2026-01-02-demo-task-tighten-trigger" in out


def test_recurrences_ignores_evidence_from_before_the_fix(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _implemented(root)
    proposal(root, "2026-01-01-older-task-same-target", folder="rejected", status="rejected")
    (root / "work" / "_learning" / "audit-history" / "2026-01-04.md").write_text(
        "skills/demo/SKILL.md drift\n", encoding="utf-8")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "recurrences", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_recurrences_ignores_a_different_target(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _implemented(root)
    proposal(root, "2026-02-01-other-task-other-file", target_path="skills/other/SKILL.md")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "recurrences", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_recurrences_never_changes_a_status(tmp_path):
    root = bridge_root(tmp_path)
    _implemented(root)
    later = proposal(root, "2026-02-01-other-task-trigger-again")
    before = sorted(p.read_text(encoding="utf-8")
                    for p in (root / "work" / "_learning").rglob("*.md"))

    assert ll.main(["--root", str(root), "recurrences"]) == 0
    after = sorted(p.read_text(encoding="utf-8")
                   for p in (root / "work" / "_learning").rglob("*.md"))
    assert before == after
    assert frontmatter(later)["status"] == "pending"


# ---------------------------------------------------------------------------
# prior-rejections (#204): writers consult rejected/ before writing
# ---------------------------------------------------------------------------


def test_schema_accepts_prior_rejections_and_the_audit_fingerprint():
    data = _base()
    data["prior_rejections"] = [{"id": "2026-01-01-fixture-topic", "reason": "parent task failed"}]
    data["source"]["fingerprint"] = "3f2a8b1c" * 8
    assert list(_validator().iter_errors(data)) == []
    data["prior_rejections"] = [{"id": "2026-01-01-fixture-topic"}]
    assert list(_validator().iter_errors(data)), "reason is required in a citation"


def _rejected_fixture(root):
    return proposal(root, "2026-01-01-fixture-topic", folder="rejected", status="rejected",
                    target_path="skills/fixture-skill/SKILL.md",
                    extra={"rejected_at": "2026-01-01", "reject_reason": "parent task failed"})


def test_prior_rejections_finds_a_rejection_on_the_same_target_path(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _rejected_fixture(root)

    capsys.readouterr()
    assert ll.main(["--root", str(root), "prior-rejections",
                    "skills/fixture-skill/SKILL.md", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == [
        {"id": "2026-01-01-fixture-topic", "reason": "parent task failed"}]


def test_prior_rejections_ignores_a_different_target_even_with_the_same_task(tmp_path, capsys):
    root = bridge_root(tmp_path)
    _rejected_fixture(root)  # source.task_slug is demo-task

    capsys.readouterr()
    assert ll.main(["--root", str(root), "prior-rejections",
                    "skills/other-skill/SKILL.md", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_prior_rejections_ignores_pending_and_accepted_proposals(tmp_path, capsys):
    root = bridge_root(tmp_path)
    proposal(root, "2026-01-01-pending-topic", target_path="skills/fixture-skill/SKILL.md")
    proposal(root, "2026-01-01-accepted-topic", folder="accepted", status="implemented",
             target_path="skills/fixture-skill/SKILL.md")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "prior-rejections",
                    "skills/fixture-skill/SKILL.md", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_prior_rejections_falls_back_to_the_trail_reason(tmp_path, capsys):
    root = bridge_root(tmp_path)
    proposal(root, "2026-01-01-fixture-topic", folder="rejected", status="rejected",
             target_path="skills/fixture-skill/SKILL.md")
    trail = root / "work" / "_learning" / "audit-trail.md"
    trail.write_text(trail.read_text(encoding="utf-8")
                     + "| 2026-01-01 10:00 | 2026-01-01-fixture-topic | pending → rejected "
                       "| covered by another skill | — |\n", encoding="utf-8")

    capsys.readouterr()
    assert ll.main(["--root", str(root), "prior-rejections",
                    "skills/fixture-skill/SKILL.md", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["reason"] == "covered by another skill"


def test_prior_rejections_plain_output_says_none_found(tmp_path, capsys):
    root = bridge_root(tmp_path)

    capsys.readouterr()
    assert ll.main(["--root", str(root), "prior-rejections", "skills/x/SKILL.md"]) == 0
    assert "no rejected proposal" in capsys.readouterr().out
