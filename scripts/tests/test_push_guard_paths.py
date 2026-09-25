"""The push guard's content net, held to the tree it guards.

`scripts/hooks/pre-push` blocks USER content on its way to a public or unknown
remote by PATH (`USER_PATHS`), minus the CORE companions that live inside those
paths (`CORE_EXEMPT`). Both were hand-kept lists of family names. Measured on
2026-09-25, before this file existed, four kinds of instance data were missing
from the net: `identity/vehicles/`, `infra/secret-stores/`,
`infra/object-stores/` and the root `ecosystem.yaml` and
`context-budget.user.yaml`. Nobody noticed, because the shipped `.gitignore`
kept those files out of every commit. Once a private instance tracks its own
data, the net is the only thing between that data and a public remote, so it
has to know every family the tree has, including the next one.

The two assertions: every family in the tree, and every root instance file, is
caught; and nothing CORE ships is caught, or `/promote` breaks.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOK = (REPO / "scripts" / "hooks" / "pre-push").read_text()


def _regex(name: str) -> re.Pattern:
    m = re.search(rf"^{name}='([^']+)'", HOOK, re.M)
    assert m, f"{name} is no longer a single-quoted assignment in pre-push"
    return re.compile(m.group(1))


USER_PATHS = _regex("USER_PATHS")
CORE_EXEMPT = _regex("CORE_EXEMPT")


def _families() -> list:
    return sorted(f"{w}/{d.name}" for w in ("identity", "infra", "workflow")
                  for d in (REPO / w).iterdir() if d.is_dir())


def _caught(path: str) -> bool:
    return bool(USER_PATHS.search(path)) and not CORE_EXEMPT.search(path)


@pytest.mark.parametrize("family", _families())
def test_every_family_in_the_tree_is_caught(family):
    assert _caught(f"{family}/mine.yaml"), family
    assert _caught(f"{family}/nested/deeper/README.md"), family


def test_a_family_the_tree_does_not_have_yet_is_caught():
    assert _caught("workflow/meetings/weekly.yaml")
    assert _caught("identity/voiceprints/README.md")    # biometric, never exempt


@pytest.mark.parametrize("path", [
    "bridge-config.yaml", "ecosystem.yaml", "ecosystem.bks.yaml", "ecosystem.my_org.yaml",
    "ecosystem.BKS.yaml", "ecosystem.acme.eu.yaml", "overlays.lock.yaml",
    "workspaces.lock.yaml", "context-budget.user.yaml", "edges.yaml",
    "reachability-scenarios.yaml", "bridge-deck.config.yaml",
    "identity/agent/SOUL.md", "work/memory/user_role.md",
    # the negation files a private instance commits: promoting one would strip
    # every public clone of its protection
    "identity/.gitignore", "infra/.gitignore", "workflow/.gitignore", "work/.gitignore",
])
def test_every_root_instance_file_is_caught(path):
    assert _caught(path), path


def _user_data():
    spec = importlib.util.spec_from_file_location(
        "user_data_for_push_guard", REPO / "scripts" / "user-data.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_everything_user_data_calls_an_instance_file_is_caught():
    """Two definitions of the same set, held to each other on every family."""
    ud = _user_data()
    samples = [f"{f}/{leaf}" for f in _families()
               for leaf in ("x.yaml", "sub/x.yaml", "x.md")]
    samples += list(ud.ROOT_FILES) + list(ud.NEGATION_FILES) + ["ecosystem.my_org.yaml"]
    missed = [p for p in samples if ud.is_instance_path(p) and not _caught(p)]
    assert missed == [], missed


def test_nothing_core_ships_is_caught():
    """CORE by the scope router, so the test also holds inside a private instance."""
    spec = importlib.util.spec_from_file_location(
        "router_for_push_guard", REPO / "scripts" / "categorize-commits.py")
    router = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = router
    spec.loader.exec_module(router)
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files"], check=True,
                             capture_output=True, text=True).stdout.splitlines()
    core = [p for p in tracked if router.classify_file(p) == "core"]
    caught = [p for p in core if _caught(p)]
    assert caught == [], (
        "CORE files the push guard would block on a promote; exempt them in "
        f"CORE_EXEMPT or move them under a _-prefixed name: {caught}")
