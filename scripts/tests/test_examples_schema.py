#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Every shipped example instance validates against the CORE schema of its family.

WHY THIS EXISTS. `scripts/validate-bridge.py` globs from the repo root, so the
worked examples under `examples/<name>/` were never validated by anything: they
are the files a newcomer copies first, and a field that drifted there would be
copied into every new instance. This suite points the root schemas at each
example tree instead. It discovers examples and families by walking, so a third
example or a new schema-bearing family is covered without editing this file.

What is checked:

  - every `<family>/**/*.yaml` inside an example whose family has a root
    `_schema.yaml` (skipping `_`-prefixed files, which are templates or
    sidecars such as `infra/backups/_state.yaml`);
  - the frontmatter of every `work/**/STATUS.md` against
    `work/templates/_schema.status.yaml`.

Families without a root schema (`infra/utilities/` today) are skipped, and the
test named `test_unschemaed_families_are_listed` prints them so the gap stays
visible rather than reading as coverage.

KNOWN_DRIFT names files that fail today and are owned by someone else's change.
It may only shrink: a listed file that starts passing fails the suite, so the
entry gets removed in the same change that fixed it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jsonschema = pytest.importorskip("jsonschema")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES = REPO_ROOT / "examples"
CLUSTERS = ("identity", "infra", "workflow")
STATUS_SCHEMA = REPO_ROOT / "work" / "templates" / "_schema.status.yaml"

# examples/agency predates the required `sync.bridge_only` key: its tasks bound
# to GitHub omit it. Fixing that edits examples/agency, which is out of scope
# for the change that added this suite.
KNOWN_DRIFT = frozenset({
    "examples/agency/work/tasks/bigcorp-api-payment-retry/STATUS.md",
    "examples/agency/work/tasks/cart-a11y-pass/STATUS.md",
    "examples/agency/work/tasks/startupxyz-onboarding/STATUS.md",
    "examples/agency/work/done/2026-06/dark-mode-toggle/STATUS.md",
})


def _plain(data):
    """YAML dates become strings, as check-jsonschema and extract-frontmatter do."""
    return json.loads(json.dumps(data, default=str))


def _load_schema(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _example_dirs() -> list[Path]:
    return sorted(p for p in EXAMPLES.iterdir() if p.is_dir()) if EXAMPLES.exists() else []


def _families() -> list[str]:
    out = []
    for cluster in CLUSTERS:
        for fam in sorted((REPO_ROOT / cluster).iterdir()):
            if fam.is_dir():
                out.append(f"{cluster}/{fam.name}")
    return out


def _yaml_cases() -> list[tuple[str, str]]:
    cases = []
    for example in _example_dirs():
        for fam in _families():
            if not (REPO_ROOT / fam / "_schema.yaml").exists():
                continue
            for inst in sorted((example / fam).rglob("*.yaml")) if (example / fam).exists() else []:
                if inst.name.startswith("_"):
                    continue
                cases.append((fam, inst.relative_to(REPO_ROOT).as_posix()))
    return cases


def _status_cases() -> list[str]:
    return [
        p.relative_to(REPO_ROOT).as_posix()
        for example in _example_dirs()
        for p in sorted((example / "work").rglob("STATUS.md"))
    ]


def _errors(schema: dict, instance) -> list[str]:
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(instance)
    ]


def _frontmatter(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").split("\n")
    fences = [i for i, line in enumerate(lines) if line.strip() == "---"]
    assert len(fences) >= 2, f"{path}: no frontmatter"
    return yaml.safe_load("\n".join(lines[fences[0] + 1 : fences[1]])) or {}


def test_examples_are_discovered():
    """A walk that finds nothing would make every test below vacuously green."""
    assert _yaml_cases(), "no example instance matched any schema-bearing family"
    assert _status_cases(), "no STATUS.md found under examples/*/work/"


@pytest.mark.parametrize("family,rel", _yaml_cases(), ids=lambda v: v)
def test_example_instance_matches_family_schema(family, rel):
    schema = _load_schema(REPO_ROOT / family / "_schema.yaml")
    instance = _plain(yaml.safe_load((REPO_ROOT / rel).read_text(encoding="utf-8")))
    errors = _errors(schema, instance)
    assert not errors, f"{rel} against {family}/_schema.yaml:\n  " + "\n  ".join(errors)


@pytest.mark.parametrize("rel", _status_cases(), ids=lambda v: v)
def test_example_status_frontmatter_matches_schema(rel):
    schema = _load_schema(STATUS_SCHEMA)
    errors = _errors(schema, _plain(_frontmatter(REPO_ROOT / rel)))
    if rel in KNOWN_DRIFT:
        assert errors, f"{rel} passes now: remove it from KNOWN_DRIFT"
        pytest.xfail("known drift: " + errors[0])
    assert not errors, f"{rel}:\n  " + "\n  ".join(errors)


def test_example_status_slug_matches_folder():
    """The generated board keys on the folder name; a mismatched slug splits one task in two."""
    wrong = [
        rel for rel in _status_cases()
        if _frontmatter(REPO_ROOT / rel).get("slug") != Path(rel).parent.name
    ]
    assert not wrong, "slug differs from folder: " + ", ".join(wrong)


def test_unschemaed_families_are_listed(capsys):
    """Not a gate: names the example families nothing validates, so the gap is seen."""
    unchecked = sorted({
        fam
        for example in _example_dirs()
        for fam in _families()
        if (example / fam).exists() and not (REPO_ROOT / fam / "_schema.yaml").exists()
    })
    with capsys.disabled():
        if unchecked:
            print("\n  example families without a root schema: " + ", ".join(unchecked))
